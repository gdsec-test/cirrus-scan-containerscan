import json
import csv
import requests
import os
from io import StringIO
from time import sleep
import boto3
from datetime import datetime
from urllib3 import Retry
from common import securityhub
from errors import ExitContainerScanner, RegistrationError, ProvisioningTimeoutError, DeprovisioningScannerTimeoutError
from aws_clients import SSMClient, SecretsManagerClient, S3Client, ServiceCatalog


class PrismaClient():
    """Prisma client to fetch prisma token """

    def __init__(self, logger, sts_client, sm_client, ec2_client):
        self.logger = logger
        self.sts_client = sts_client
        self.sm_client = sm_client
        self.ec2_client = ec2_client
        
    def get_token(self, iam_role_arn):
        """Retrieves Prisma Access key and secret key id from Secret Manager"""
        
        aws_creds = self.sts_client.assume_role(iam_role_arn)
        prisma_secrets = self.sm_client.get_prisma_secrets(aws_creds)

        payload = {
            "username": prisma_secrets["prismaAccessKeyId"],
            "password": prisma_secrets["prismaSecretKey"],
        }

        response = self.create_prisma_api_request(
            "POST", url="/authenticate", payload=payload)

        text_json = json.loads(response.text)
        token = text_json["token"]
        return token

    def register_ecr_registry(self, token, ecr_registry_name, vpc_id):
        """Register ECR registry with Prisma"""
     
        response = self.ec2_client.describe_instances(vpc_id)

        region = boto3.session.Session().region_name
        account_id = boto3.client("sts").get_caller_identity().get("Account")
        scanner_name = "cirrusscan" + "-" + account_id + "-" + region + "-" + vpc_id

        try:
            scanner_dnsname = response["Reservations"][0]["Instances"][0]["NetworkInterfaces"][
                0
            ]["PrivateDnsName"]
            self.logger.info("Scanner name : %s" % scanner_dnsname)
        except KeyError:
            self.logger.error("Scanner IP not found")
            scanner_dnsname = None

        if scanner_dnsname is None:
            raise RegistrationError

        # register ECR registry
        # curl -H "Authorization: Bearer "${TOKEN}"" -X POST -d '{"registry":"226955763576.dkr.ecr.us-west-2.amazonaws.com","repository":"","tag":"","cap":5,"os":"linux","hostname":"","namespace":"","useAWSRole":true,"version":"aws","credential":{"_id":"","type":"","accountID":"","accountGUID":"","secret":{"encrypted":""},"apiToken":{"encrypted":""},"lastModified":"0001-01-01T00:00:00Z","owner":"","tokens":null},"credentialID":"","roleArn":"","scanners":1,"versionPattern":""}' https://us-east1.cloud.twistlock.com/us-2-158254964/api/v1/settings/registry
        payload_template = '{"registry":"","repository":"","tag":"","cap":5,"os":"linux","hostname":"","namespace":"","useAWSRole":true,"version":"aws","credentialID":"","roleArn":"","scanners":1,"versionPattern":""}'
        payload = json.loads(payload_template)
        payload["registry"] = ecr_registry_name
        payload["hostname"] = scanner_dnsname

        self.logger.debug("registry payload : %s" % payload)
        # self.logger.debug("token : %s" % token)

        self.create_prisma_api_request(
            "POST", "/settings/registry", token=token, payload=payload)

        self.logger.info(
            f"Registered {scanner_dnsname} with ECR registry {ecr_registry_name}!")

    def force_ecr_registry_scan(self, token, ecr_registry_name):
        
        payload_template = '{ "tag" : { "registry" : "" } }'
        payload = json.loads(payload_template)
        payload["tag"]["registry"] = ecr_registry_name
      
        response = self.create_prisma_api_request(
            "POST", "/registry/scan", token=token, payload=payload)

        self.logger.info(f"Forced scan of ECR registry {ecr_registry_name}!")

    def retrieve_scanner_results(self, token, ecr_registry_name):
        
        param = "registry=" + ecr_registry_name

        # all results in csv format
        response = self.create_prisma_api_request(
            "GET", "/registry/download", token=token, params=param)

        self.logger.info(
            f"Retrieve scan results from ECR registry {ecr_registry_name}.")
        return response.text

    def wait_for_scan_completion(self):
        """Wait for the scan to be completed"""

        self.logger.info("Waiting for Container Scan to finish")
        # sleep for ?? minutes due to lack of progress api
        #TODO change to 30
        sleep(30*60)

    def create_prisma_api_request(self, method, url, token=None, payload=None, params=None):
        """Helper function to make Prisma API requests"""
        PRISMA_COMPUTE_REST_API_URL = "https://us-east1.cloud.twistlock.com/us-2-158254964/api/v1"
        headers = None
        response = None
        payload = json.dumps(payload)

        # As we may hit Prisma API limits, try hitting Prisma at least 3 times before shutting down Vulnerability Scanner
        retries = Retry(
            total=3,
            status_forcelist={429, 501, 502, 503, 504},
            backoff_factor=1,
            respect_retry_after_header=True,
        )

        if token is not None:
            headers = {"Authorization": "Bearer " + token}
        else:
            headers = {"content-type": "application/json"}

        try:
            adapter = requests.adapters.HTTPAdapter(max_retries=retries)

            # initiate the session and then attach the Retry adaptor.
            session = requests.Session()
            session.mount("https://", adapter)

            session.headers = headers
            fullurl = PRISMA_COMPUTE_REST_API_URL + url   
         
            if method == "POST":
                response = session.post(
                    fullurl, params=params, data=payload, timeout=5.0)
            else:                
                response = session.get(
                    fullurl, params=params, data=payload, timeout=5.0)

            if response.status_code == 200:
                return response
        except:
            self.logger.exception(
                "Exception occurred in making Prisma request")

        self.logger.error(
            f"Prisma API call from {url} method returning status code: {response.status_code}.")

        self.logger.error(
            f"Prisma API call failed from method: {url}. Exiting!")
        raise ExitContainerScanner


class Scanner():        
    def __init__(self, logger, s3_client, sc_client, ssm_client,provisioned_product_name,task_name):
        self.logger = logger
        self.s3_client = s3_client
        self.sc_client = sc_client
        self.ssm_client = ssm_client
        self.provisioned_product_name =provisioned_product_name
        self.task_name = task_name

    def save_scanner_results(self, results):
        """Save scanner results to an S3 bucket."""
        self.logger.info("Saving Prisma scanner results")

        results_bucket = os.getenv("CIRRUS_SCAN_RESULTS_BUCKET")
        task_uuid = os.getenv("CIRRUS_SCAN_TASK_UUID", "UNDEFINED")
        results_key = "containerscan/%s/results.csv" % task_uuid
        
        temp_csv = "/tmp/results.csv"
        container_results_csv = open(temp_csv, "w")
        csv_writer = csv.writer(container_results_csv)
        
        with StringIO(results) as input_file:
            csv_reader = csv.reader(input_file, delimiter=",", quotechar='"')
            for row in csv_reader:
                csv_row = row
                csv_writer.writerow(csv_row)

        container_results_csv.close()

        self.s3_client.upload_file(temp_csv, results_bucket, results_key)

        if os.path.isfile(temp_csv):
            os.remove(temp_csv)

    def evaluate_scanner_results(self, vpc_id, handle, csv_results):
        """Evaluate scanner results and generate Security Hub findings."""
        self.logger.info("Evaluating Prisma scanner results")

        csv_results = csv.DictReader(csv_results.split("\r\n"), delimiter=",")

        for result in csv_results:
            if result["Risk"] in ("Low", "Medium", "High"):
                severity = result.get("Risk", "NONE")
                title = result.get("Name", "UNKNOWN")
                description = result.get("Synopsis", "")
                solution = result.get("Solution", "")
                url = result.get("See Also", "None").split("\n")[0]
                host = result.get("Host", "")

                title_id = title.replace(" ", "-")

                # Generate a SecurityHub finding
                overrides = {}
                overrides["Id"] = "vulnscan/%s/%s/%s/%s" % (
                    handle.aws_region(),
                    vpc_id,
                    host,
                    title_id,
                )
                overrides["Title"] = "Vulnerability Scan [%s, %s]" % (
                    handle.aws_region(),
                    title,
                )
                overrides["Description"] = (
                    "The Prisma scanner detected an issue (%s)" % description
                )
                overrides["Remediation"] = {
                    "Recommendation": {"Text": solution}}
                overrides["Resources"] = [
                    {"Type": "AwsEc2Instance", "Id": host,
                        "Region": handle.aws_region()}
                ]

                overrides["GeneratorId"] = "Vulnerability Scan"
                overrides["Compliance"] = {"Status": "FAILED"}

                if url != "":
                    overrides["SourceUrl"] = url

                if severity == "High":
                    overrides["Severity"] = securityhub.set_severity(
                        75, original=severity
                    )
                elif severity == "Medium":
                    overrides["Severity"] = securityhub.set_severity(
                        50, original=severity
                    )
                elif severity == "Low":
                    overrides["Severity"] = securityhub.set_severity(
                        25, original=severity
                    )
                try:
                    finding = handle.Finding(
                        overrides["Id"], override_dict=overrides)
                    finding.save()
                except Exception:
                    self.logger.exception(
                        "Error while processing scanner result:")

    def generate_informational_finding(self, handle):
        """Generate an informational finding indicating test is complete"""

        self.logger.debug("Test complete")
        utcnow = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        # Generate a Security Hub finding
        finding_id = "vulnscan/complete/%s/%s" % (
            handle.aws_region(), "SOME_VPC_MOCK")
        finding = handle.Finding(finding_id)

        finding.ProductFields["Environment"] = os.getenv(
            "CIRRUS_SCAN_ACCOUNT_ENVIRONMENT", "UNKNOWN")
        finding.ProductFields["TaskUuid"] = os.getenv(
            "CIRRUS_SCAN_TASK_UUID", "UNKNOWN")
        finding.ProductFields["TeamName"] = os.getenv(
            "CIRRUS_SCAN_ACCOUNT_TEAM_NAME", "UNKNOWN")

        finding.Title = "Vulnscan: [%s, %s] finished at %s" % (
            handle.aws_region(),
            "SOME_VPC_MOCK",
            utcnow,
        )
        finding.Compliance = {"Status": "PASSED"}
        finding.Description = "No description available."
        finding.GeneratorId = "Vulnscan"
        finding.LastObservedAt = utcnow

        finding.save()

    def remove(self):
        
        if(self.sc_client.provisioned_product_exists(self.provisioned_product_name)):
            self.sc_client.deprovision_scanner(self.provisioned_product_name)
        if(self.ssm_client.has_task_parameter(self.task_name)):    
            self.ssm_client.delete_task_parameter(self.task_name)