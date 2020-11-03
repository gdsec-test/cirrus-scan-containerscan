import os
import json
import csv
from time import sleep
from requests.packages.urllib3.util.retry import Retry
import common.securityhub
from .errors import SecretManagerRetrievalError, ExitContainerScanner, ForceScanError, RegistrationError, ProvisioningTimeoutError
from .aws_clients import SecurityTokenServiceClient, SecretsManagerClient, EC2Client, S3Client, ServiceCatalog
from .utils import load_in_script

CIRRUS_SCAN_BUCKET_ENV_NAME = "CIRRUS_SCAN_RESULTS_BUCKET"


class Prisma():
    def __init__(self, logger):
        self.sts_client = SecurityTokenServiceClient(logger)
        self.logger = logger

    @staticmethod
    def determine_audit_role_arn(accounts_bucket):
        if "dev-private" in accounts_bucket:
            return "arn:aws:iam::878238275157:role/GD-AuditFramework-SecretsManagerReadOnlyRole"
        elif "gd-audit-prod-cirrus-scan-results-p" in accounts_bucket:
            return "arn:aws:iam::339078146124:role/GD-AuditFramework-SecretsManagerReadOnlyRole"
        elif "gd-audit-prod-cirrus-scan-results-h" in accounts_bucket:
            return "arn:aws:iam::512827982966:role/GD-AuditFramework-SecretsManagerReadOnlyRole"
        elif "gd-audit-prod-cirrus-scan-results-r" in accounts_bucket:
            return "arn:aws:iam::906957162968:role/GD-AuditFramework-SecretsManagerReadOnlyRole"
        elif "gd-audit-prod-cirrus-scan-results" in accounts_bucket:
            return "arn:aws:iam::672751022979:role/GD-AuditFramework-SecretsManagerReadOnlyRole"
        return None

    @staticmethod
    def create_prisma_auth(prisma_secrets):
        auth_dict = dict()
        auth_dict["password"] = prisma_secrets["id"]
        auth_dict["username"] = prisma_secrets["secretKey"]

        prisma_auth = json.dumps(auth_dict)
        return prisma_auth

    def get_token(self):
        """Retrieves Prisma Access key and secret key id from Secret Manager"""

        accounts_bucket = self.get_accounts_bucket()
        audit_role_arn = self.get_audit_role_arn(accounts_bucket)
        screts_mananger_creds = self.get_screts_mananger_creds(audit_role_arn)
        prisma_secrets = self.get_prisma_token_secrets(screts_mananger_creds)
        prisma_auth = self.create_prisma_auth(prisma_secrets)

        response = self.create_prisma_api_request(
            "GET", url="authenticate", payload=prisma_auth)

        self.logger.debug(
            "get_token: response status_code {}".format(
                response.status_code
            )
        )

        text_json = json.loads(response.text)
        token = text_json["token"]
        return token

    def get_accounts_bucket(self):
        # Get the global audit account
        accounts_bucket = os.getenv(CIRRUS_SCAN_BUCKET_ENV_NAME)
        if not accounts_bucket:
            self.logger.error(
                "Error in retrieving Global Account bucket details. Exiting!")
            raise SecretManagerRetrievalError

        return accounts_bucket

    def get_audit_role_arn(self, accounts_bucket):
        auditRoleArn = self.determine_audit_role_arn(accounts_bucket)
        if auditRoleArn is None:
            self.logger.error(
                "Error in retrieving auditRoleArn. Exiting!")
            raise SecretManagerRetrievalError

        self.logger.info("AuditRoleARN: %s", auditRoleArn)

        return auditRoleArn

    def get_screts_mananger_creds(self, audit_role_arn):
        # Get API keys from Global Audit account
        secrets_manager_creds = self.sts_client.assume_role(audit_role_arn)
        if secrets_manager_creds is None:
            self.logger.error("assume_role call failed")
            raise SecretManagerRetrievalError

        return secrets_manager_creds

    def get_prisma_token_secrets(self, secrets_manager_creds):
        sm_client = SecretsManagerClient(self.logger, secrets_manager_creds)
        prisma_secrets = sm_client.get_prisma_token_secrets()

        if not prisma_secrets:
            self.logger.error("Unable to retrieve access keys")
            raise SecretManagerRetrievalError

        return prisma_secrets

    # TODO(lmcdade): Do we expect token to ever be empty
    def create_prisma_api_request(self, method, url, token=None, payload=None, params=None):
        """Helper function to make Prisma API requests"""

        # As we may hit Prisma API limits, try hitting Prisma at least 3 times before shutting down Vulnerability Scanner
        retries = Retry(
            total=3,
            status_forcelist={429, 501, 502, 503, 504},
            backoff_factor=1,
            respect_retry_after_header=True,
        )

        headers = None
        if token is not None:
            headers = {"Authorization": "Bearer " + token}

        response = None

        try:
            adapter = requests.adapters.HTTPAdapter(max_retries=retries)

            # initiate the session and then attach the Retry adaptor.
            session = requests.Session()
            session.mount("https://", adapter)

            # add the API keys to the session.
            session.headers = headers
            fullurl = PRISMA_COMPUTE_REST_API_URL + url
            # now make calls using session
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
            "Prisma API call from %s method returning status code: %i.",
            url,
            response.status_code,
        )

        self.logger.error(
            "Prisma API call failed from method: %s. Exiting!", url)
        raise ExitContainerScanner


class Scanner():
    def __init__(self, logger):
        self.prisma = Prisma(logger)
        self.logger = logger

    def register_ecr_registry(self, token, ecr_registry_name, vpc_id):
        """Register ECR registry with Prisma"""
        self.logger.info("Waiting for Prisma scanner registration")

        # make a call to get the name of the provisioned scanner
        ec2_client = EC2Client(self.logger)
        response = ec2_client.describe_instances(vpc_id)

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
        reg_json = self.construct_registry_settings_payload(
            ecr_registry_name, scanner_dnsname
        )
        response = self.prisma.create_prisma_api_request(
            "POST", "settings/registry", token=token, payload=json.dumps(reg_json))

        if response.status_code == 200:
            self.logger.info("Registered %s with ECR registry %s!",
                             scanner_dnsname, ecr_registry_name)
            return

        self.logger.error(
            "Unable to register %s with ECR registry %s!", scanner_dnsname, ecr_registry_name)

    def force_ecr_registry_scan(self, token, ecr_registry_name):
        # curl -H "Authorization: Bearer "${TOKEN}"" -X POST -d '{"registry":"226955763576.dkr.ecr.us-west-2.amazonaws.com","repository":"","tag":"","cap":5,"os":"linux","hostname":"","namespace":"","useAWSRole":true,"version":"aws","credential":{"_id":"","type":"","accountID":"","accountGUID":"","secret":{"encrypted":""},"apiToken":{"encrypted":""},"lastModified":"0001-01-01T00:00:00Z","owner":"","tokens":null},"credentialID":"","roleArn":"","scanners":1,"versionPattern":""}' https://us-east1.cloud.twistlock.com/us-2-158254964/api/v1/settings/registry
        reg = '{ "tag" : { "registry" : "" } }'
        reg_json = json.loads(reg)
        reg_json["registry"] = ecr_registry_name

        response = self.prisma.create_prisma_api_request(
            "POST", "/registry/scan", token=token, payload=json.dumps(reg_json))

        if response.status_code == 200:
            self.logger.info(
                "Forced scan of ECR registry %s!", ecr_registry_name)
            return
        else:
            self.logger.error("Unable to force scan of ECR registry %s!",
                              ecr_registry_name)

        raise ForceScanError

    @staticmethod
    def construct_registry_settings_payload(ecr_registry_name, scanner_dnsname):
        reg = '{"registry":"","repository":"","tag":"","cap":5,"os":"linux","hostname":"","namespace":"","useAWSRole":true,"version":"aws","credential":{"_id":"","type":"","accountID":"","accountGUID":"","secret":{"encrypted":""},"apiToken":{"encrypted":""},"lastModified":"0001-01-01T00:00:00Z","owner":"","tokens":null},"credentialID":"","roleArn":"","scanners":1,"versionPattern":""}'
        reg_json = json.loads(reg)
        reg_json["registry"] = ecr_registry_name
        reg_json["hostname"] = scanner_dnsname
        return reg_json

    def wait_for_scan_completion(self):
        """Wait for the scan to be completed"""

        self.logger.info("Waiting for Container Scan to finish")
        # sleep for 45 minutes due to lack of progress api
        sleep(45*60)

        # # This loop runs for ~60 minutes, to wait for Prisma scan completion
        # for setup_count in range(60):
        #     log.info("Getting Prisma Scan Status")
        #     time.sleep(60)

        #     offset = 1
        #     limit = 50
        #     params ={"limit":limit,"offset":offset}

        #     while True:
        #         response = create_prisma_api_request("GET", "registry/progress", token=token, params=params)
        #         data = json.loads(response.text)

        #         for x in data['registry']:
        #             ## registry still being scanned
        #             if(x == registry):
        #                 break;

        #         if len(data) < limit:
        #             ## at this point, we have exhaused the list and didnt find the one, meaning it is done.
        #             return;
        #         #continue with next page
        #         offset += limit

        # log.error("Scanning timed out")
        # raise ScanningTimeoutError

    def retrieve_scanner_results(self, token, ecr_registry_name):
        # https://us-east1.cloud.twistlock.com/us-2-158254964/api/v1/registry/download?registry="226955763576.dkr.ecr.us-east-1.amazonaws.com"
        param = "registry=" + ecr_registry_name

        # all results in csv format
        response = self.prisma.create_prisma_api_request(
            "GET", "/registry/download", token=token, params=param)

        if response.status_code == 200:
            self.logger.info(
                "Retrieve scan results from ECR registry %s.", ecr_registry_name)
            return response.text
        else:
            self.logger.error(
                "Unable to retrieve scan results from ECR registry %s.", ecr_registry_name)

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
                    overrides["Severity"] = common.securityhub.set_severity(
                        75, original=severity
                    )
                elif severity == "Medium":
                    overrides["Severity"] = common.securityhub.set_severity(
                        50, original=severity
                    )
                elif severity == "Low":
                    overrides["Severity"] = common.securityhub.set_severity(
                        25, original=severity
                    )
                try:
                    finding = handle.Finding(
                        overrides["Id"], override_dict=overrides)
                    finding.save()
                except Exception:
                    self.logger.exception(
                        "Error while processing scanner result:")

    def provision_scanner(self, vpc_id):
        """Provision a Prisma scanner, using Service Catalog product EC2"""
        self.logger.info("Provisioning Prisma scanner")

        ec2_client = EC2Client(self.logger)

        subnet_id = ec2_client.get_subnet_id(vpc_id)
        product_id = ec2_client.get_ec2_product_id()
        provisioning_artifact_id = ec2_client.get_ec2_product_description(
            product_id)

        script = load_in_script()
        provisioned_product_name = "VulnScanner-" + vpc_id
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
