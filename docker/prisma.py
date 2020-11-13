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
    SCAN_WAIT_TIME = 10
    REGISTERY_MAX_WAIT_TIME=15

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
        
        params ={'hostname':scanner_dnsname}            
        for setup_count in range(self.REGISTERY_MAX_WAIT_TIME):
            self.logger.debug("waiting for defender to report to console, loop: %d" % setup_count)
            sleep(1*60)
            response = self.create_prisma_api_request("GET", "/defenders/names",token=token,params=params )
            defenders = json.dumps(response.json())       
        
            if scanner_dnsname in defenders:
                self.logger.info("Defender reported to console, ecr %s | scanner: %s" % (ecr_registry_name, scanner_dnsname))
                break
                       
        #force sleep for defender to get to console
        # self.logger.info("Force sleep %d minutes for defender to report to console, ecr %s | scanner: %s" % (self.REGISTERY_WAIT_TIME, ecr_registry_name, scanner_dnsname))
        # sleep(self.REGISTERY_WAIT_TIME*60)

        # register ECR registry
        # curl -H "Authorization: Bearer "${TOKEN}"" -X POST -d '{"registry":"226955763576.dkr.ecr.us-west-2.amazonaws.com","repository":"","tag":"","cap":5,"os":"linux","hostname":"","namespace":"","useAWSRole":true,"version":"aws","credential":{"_id":"","type":"","accountID":"","accountGUID":"","secret":{"encrypted":""},"apiToken":{"encrypted":""},"lastModified":"0001-01-01T00:00:00Z","owner":"","tokens":null},"credentialID":"","roleArn":"","scanners":1,"versionPattern":""}' https://us-east1.cloud.twistlock.com/us-2-158254964/api/v1/settings/registry
        payload_template = '{"registry":"","repository":"","tag":"","cap":5,"os":"linux","hostname":"","namespace":"","useAWSRole":true,"version":"aws","credentialID":"","roleArn":"","scanners":1,"versionPattern":""}'
        payload = json.loads(payload_template)
        payload["registry"] = ecr_registry_name
        payload["hostname"] = scanner_dnsname
      

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

        self.logger.info("Waiting for {} minutes for Container Scan to finish".format(self.SCAN_WAIT_TIME))
        # sleep for ?? minutes due to lack of progress api       
        sleep(self.SCAN_WAIT_TIME*60)

    def create_prisma_api_request(self, method, url, token=None, payload=None, params=None):
        """Helper function to make Prisma API requests"""
        PRISMA_COMPUTE_REST_API_URL = "https://us-east1.cloud.twistlock.com/us-2-158254964/api/v1"
        headers = None
        response = None
        payload = json.dumps(payload)

        if payload is not None and "username" not in payload:
            self.logger.debug("url: %s |method: %s  |payload : %s" % (url , method , payload))
        if params is not None:
            self.logger.debug("params: %s" % params )
        
        # As we may hit Prisma API limits, try hitting Prisma at least 3 times before shutting down Container Scanner
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
    def __init__(self, logger, s3_client, sc_client, ssm_client, provisioned_product_name, task_name):
        self.logger = logger
        self.s3_client = s3_client
        self.sc_client = sc_client
        self.ssm_client = ssm_client
        self.provisioned_product_name = provisioned_product_name
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

    def evaluate_scanner_results(self, handle, csv_results):
        """Evaluate scanner results and generate Security Hub findings.

        Two things will happen
        1. Convert CSV Result from Prisma to easily consumable format.

        ```
        prisma_results = {
            "<repository_name>" : {
                "<tag>": {
                    "<package_1>": [row_resource, row_resource, row_resource, ...],
                    "<package_2>": [row_resource, row_resource, row_resource, ...],
                    ...
                    "gd_prisma_compliance": [row_resource, row_resource, ...]
                },
                ...
            },
            ...
        }
        ```

        2. Create corresponding ASFF payload object and publish.
        """
        self.logger.info("Evaluating Prisma scanner results")

        prisma_results = {}  # Logical grouping of csv interpretation
        gd_compliance_type = "gd_prisma_compliance"
        aws_region = handle.aws_region()

        csv_results = csv.DictReader(csv_results.splitlines(), delimiter=",")

        for result in csv_results:
            severity = result.get("Severity", "NONE").capitalize()

            if severity == "None":
                self.logger.warn(
                    "Unexpected : Row with no Severity found - Skipping.")
                continue

            # Only process High/Critical finding
            if severity not in set({"High", "Critical"}):
                continue

            repository_name = result["Repository"]
            repository_id = result["Id"]
            tag = result["Tag"]

            if not prisma_results.get(repository_name):
                prisma_results[repository_name] = {}

            if not prisma_results[repository_name].get(tag):
                prisma_results[repository_name][tag] = {}

            container_map = prisma_results[repository_name][tag]

            row_resource = {
                "CVSS": result.get("CVSS"),
                "Description": result.get("Description"),
                "Id": repository_id,
                "Severity": severity,
                "Vulnerability ID": result.get("Vulnerability ID"),
                "Vulnerability Type": result.get("Type"),
            }

            if result.get("CVE ID"):
                row_resource["CVE ID"] = result.get("CVE ID")
                row_resource["Package Version"] = result.get(
                    "Package Version"),
                row_resource["Fix Status"] = result.get("Fix Status"),
                row_resource["Problem"] = result.get(
                    "Source Package") or result.get("Packages")
            else:
                row_resource["Problem"] = gd_compliance_type

            if not container_map.get(row_resource["Problem"]):
                container_map[row_resource["Problem"]] = []

            container_map[row_resource["Problem"]].append(row_resource)

        self.logger.info("Finished reading csv file, generating findings...")

        for repository, tag_map in prisma_results.items():
            for tag, problem_map in tag_map.items():
                for problem, resources in problem_map.items():
                    repo_id = None
                    severity = "High"
                    resource_dict = {}

                    if problem == gd_compliance_type:
                        for r in resources:
                            if r['Severity'] == 'Critical':
                                severity = r['Severity']

                            if repo_id is None:
                                repo_id = r['Id']

                            res_id = f"Compliance-{r['Vulnerability ID']}"
                            details = f"Vulnerability Type: {r['Vulnerability Type']}\r\n Description: {r['Description']}"
                            resource_dict[res_id] = details
                    else:
                        for r in resources:
                            if r['Severity'] == 'Critical':
                                severity = r['Severity']

                            if repo_id is None:
                                repo_id = r['Id']

                            details = f"Problem: {problem}\r\n Package Version: {r['Package Version']}\r\n Fix Status: {r['Fix Status']}\r\n URL: https://nvd.nist.gov/vuln/detail/{r['CVE ID']}"
                            resource_dict[r['CVE ID']] = details

                    asff_payload = {
                        "Id": f"containerscan/{aws_region}/{repository}/{tag}/{problem}",
                        "Title": f"Container Scan [{aws_region}]: Vulnerability found with {problem} in {repository}:{tag}",
                        "Description": f"One or more vulnerabilities were found with {repository}:{tag} in {aws_region}.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "Please resolve vulnerabilities found with in ECR, take a look at Resources section within the finding for more details."
                            }
                        },
                        "GeneratorId": "Container Scan",
                        "Resources": [
                            {
                                "Type": "Container",
                                "Id": repo_id,
                                "Region": aws_region
                            },
                            {
                                "Type": "Other",
                                "Id": problem,
                                "Region": aws_region,
                                "Details": {
                                    "Other": resource_dict
                                }
                            }
                        ],
                        # TODO : Comeback and modify severity normalization.
                        "Severity": securityhub.set_severity(0, original=severity)
                    }

                    try:
                        finding = handle.Finding(
                            asff_payload["Id"], override_dict=asff_payload)
                        finding.save()
                    except Exception:
                        self.logger.exception(
                            "Error while processing scanner result:")

    def generate_informational_finding(self, handle):
        """Generate an informational finding indicating test is complete"""

        self.logger.debug("Test complete")
        utcnow = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        aws_region = handle.aws_region()

        # Generate a Security Hub finding
        finding_id = f"containerscan/complete/{aws_region}"
        finding = handle.Finding(finding_id)

        finding.ProductFields["Environment"] = os.getenv(
            "CIRRUS_SCAN_ACCOUNT_ENVIRONMENT", "UNKNOWN")
        finding.ProductFields["TaskUuid"] = os.getenv(
            "CIRRUS_SCAN_TASK_UUID", "UNKNOWN")
        finding.ProductFields["TeamName"] = os.getenv(
            "CIRRUS_SCAN_ACCOUNT_TEAM_NAME", "UNKNOWN")

        finding.Title = f"Container Scan [{aws_region}]: finished at {utcnow}"
        finding.Compliance = {"Status": "PASSED"}
        finding.Description = "No description available."
        finding.GeneratorId = "Container Scan"
        finding.LastObservedAt = utcnow

        try:
            finding.save()
        except Exception:
            self.logger.exception(
                "Error while processing scanner completed result:")

    def remove(self):

        if(self.sc_client.provisioned_product_exists(self.provisioned_product_name)):
            self.sc_client.deprovision_scanner(self.provisioned_product_name)
        if(self.ssm_client.has_task_parameter(self.task_name)):
            self.ssm_client.delete_task_parameter(self.task_name)
