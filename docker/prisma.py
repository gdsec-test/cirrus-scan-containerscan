import json
import csv
import requests
import os
from time import sleep
from urllib3 import Retry
from .common import securityhub
from .errors import ExitContainerScanner, RegistrationError, ProvisioningTimeoutError, DeprovisioningScannerTimeoutError
from .aws_clients import EC2Client, S3Client, ServiceCatalog


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
            "GET", url="/authenticate", payload=payload)

        text_json = json.loads(response.text)
        token = text_json["token"]
        return token

    def register_ecr_registry(self, token, ecr_registry_name, vpc_id):
        """Register Scanner Instance with ECR registry in Prisma"""
        self.logger.info("Waiting for Prisma scanner registration")

        # make a call to get the name of the provisioned scanner
        response = self.ec2_client.describe_instances(vpc_id)

        scanner_dnsname = None
        try:
            scanner_dnsname = response["Reservations"][0]["Instances"][0]["NetworkInterfaces"][0]["PrivateDnsName"]
            self.logger.info("Scanner name : %s" % scanner_dnsname)
        except KeyError:
            self.logger.error("Scanner IP not found")

        if scanner_dnsname is None:
            raise RegistrationError

        # register ECR registry
        # curl -H "Authorization: Bearer "${TOKEN}"" -X POST -d '{"registry":"226955763576.dkr.ecr.us-west-2.amazonaws.com","repository":"","tag":"","cap":5,"os":"linux","hostname":"","namespace":"","useAWSRole":true,"version":"aws","credential":{"_id":"","type":"","accountID":"","accountGUID":"","secret":{"encrypted":""},"apiToken":{"encrypted":""},"lastModified":"0001-01-01T00:00:00Z","owner":"","tokens":null},"credentialID":"","roleArn":"","scanners":1,"versionPattern":""}' https://us-east1.cloud.twistlock.com/us-2-158254964/api/v1/settings/registry
        payload_template = '{"registry":"","repository":"","tag":"","cap":5,"os":"linux","hostname":"","namespace":"","useAWSRole":true,"version":"aws","credential":{"_id":"","type":"","accountID":"","accountGUID":"","secret":{"encrypted":""},"apiToken":{"encrypted":""},"lastModified":"0001-01-01T00:00:00Z","owner":"","tokens":null},"credentialID":"","roleArn":"","scanners":1,"versionPattern":""}'
        payload = json.loads(payload_template)
        payload["registry"] = ecr_registry_name
        payload["hostname"] = scanner_dnsname

        self.create_prisma_api_request(
            "POST", "/settings/registry", token=token, payload=payload)

        self.logger.info(
            f"Registered {scanner_dnsname} with ECR registry {ecr_registry_name}!")

    def force_ecr_registry_scan(self, token, ecr_registry_name):
        # curl -H "Authorization: Bearer "${TOKEN}"" -X POST -d '{"registry":"226955763576.dkr.ecr.us-west-2.amazonaws.com","repository":"","tag":"","cap":5,"os":"linux","hostname":"","namespace":"","useAWSRole":true,"version":"aws","credential":{"_id":"","type":"","accountID":"","accountGUID":"","secret":{"encrypted":""},"apiToken":{"encrypted":""},"lastModified":"0001-01-01T00:00:00Z","owner":"","tokens":null},"credentialID":"","roleArn":"","scanners":1,"versionPattern":""}' https://us-east1.cloud.twistlock.com/us-2-158254964/api/v1/settings/registry
        payload_template = '{ "tag" : { "registry" : "" } }'
        payload = json.loads(payload_template)
        payload["registry"] = ecr_registry_name

        self.create_prisma_api_request(
            "POST", "/registry/scan", token=token, payload=payload)

        self.logger.info(f"Forced scan of ECR registry {ecr_registry_name}!")

    def retrieve_scanner_results(self, token, ecr_registry_name):
        # https://us-east1.cloud.twistlock.com/us-2-158254964/api/v1/registry/download?registry="226955763576.dkr.ecr.us-east-1.amazonaws.com"
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
        # sleep for 45 minutes due to lack of progress api
        sleep(45*60)

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
            headers = {"content-type": "application/json; charset=UTF-8"}

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
    def __init__(self, logger):
        self.logger = logger

    def save_scanner_results(self, results):
        """Save scanner results to an S3 bucket."""
        self.logger.info("Saving Prisma scanner results")

        results_bucket = os.getenv("CIRRUS_SCAN_RESULTS_BUCKET")
        task_uuid = os.getenv("CIRRUS_SCAN_TASK_UUID", "UNDEFINED")
        results_key = "containerscan/%s/results.csv" % task_uuid

        csv_results = csv.reader(results.split("\r\n"), delimiter=",")

        temp_csv = "/tmp/results.csv"
        container_results_csv = open(temp_csv, "w")
        csv_writer = csv.writer(container_results_csv)

        for result in csv_results:
            csv_row = result
            csv_writer.writerow(csv_row)

        container_results_csv.close()
        s3_client = S3Client(self.logger)
        s3_client.upload_file(temp_csv, results_bucket, results_key)

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

    def provision_scanner(self, provisioned_product_name, vpc_id):
        """Provision a Prisma scanner, using Service Catalog product EC2"""
        self.logger.info("Provisioning Prisma scanner")

        ec2_client = EC2Client(self.logger)

        subnet_id = ec2_client.get_subnet_id(vpc_id)
        product_id = ec2_client.get_ec2_product_id()
        provisioning_artifact_id = ec2_client.get_ec2_product_description(
            product_id)

        script = load_in_script()
        provisioned_product_id = ec2_client.provision_ec2(
            provisioned_product_name,
            product_id,
            provisioning_artifact_id,
            vpc_id,
            subnet_id,
            script)

        # Wait for product to be provisioned
        for setup_count in range(15):
            response = ec2_client.describe_provisioned_product(
                provisioned_product_id)
            if response["ProvisionedProductDetail"]["Status"] == "AVAILABLE":
                self.logger.info(
                    "Vulnerability Scanner successfully provisioned")
                break
            sleep(60)
        else:
            self.logger.error("Provisioning timed out")
            self.logger.error(response)
            raise ProvisioningTimeoutError
        return provisioned_product_name

    def deprovision_scanner(self, provisioned_product_name):
        """Deprovision a Prisma scanner, using CloudFront, Service Catalog, EC2, etc."""
        self.logger.info("Deprovisioning container scanner")

        # Terminate VulnScanner Service Catalog Product from AWS account
        sc_client = ServiceCatalog(self.logger)
        sc_client.terminate_provisioned_product(provisioned_product_name)
        # wait for deprovisioning to complete
        for setup_count in range(15):
            if not provisioned_product_exists(provisioned_product_name):
                break
            time.sleep(60)
        else:
            self.logger.error("Deprovisioning timed out")
            raise DeprovisioningScannerTimeoutError
