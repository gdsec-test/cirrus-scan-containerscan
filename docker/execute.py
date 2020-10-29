#!/usr/bin/env python3


import base64
import csv
import datetime
import json
import logging
import math
import os
from random import randint
import time
import boto3
import botocore
import requests
from botocore.exceptions import ClientError
from requests.packages.urllib3.util.retry import Retry
import common.securityhub
import tenable_instance
import wrapper

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# Deploy scanner instances using this ServiceCatalog offering version
SC_EC2_VERSION = "2.0.2"

PRISMA_COMPUTE_REST_API_URL = "https://us-east1.cloud.twistlock.com/us-2-158254964/api/v1/"

class ProvisioningTimeoutError(Exception):
    """Provision operation timed out"""

    pass


class RegistrationError(Exception):
    """ECR registry registration operation error"""

    pass

class ForceScanError(Exception):
    """Force scan operation error"""

    pass

class ScanningTimeoutError(Exception):
    """Scanning operation timed out"""

    pass


class DeprovisioningScannerTimeoutError(Exception):
    """VulnScanner Product not de-provisioned successfully"""

    pass


class SecretManagerRetrievalError(Exception):
    """Unable to retrieve Tenable API keys from Secret Manager"""

    pass


class ExitContainerScanner(Exception):
    """One of the resources required to run ContainerScanner is missing. Exiting!"""

    pass


def assume_role(role_arn):
    """Attempt to assume the specified role_arn"""

    sts = boto3.client("sts")

    log.info("Attempting to assume role: %s", role_arn)

    try:
        response = sts.assume_role(RoleArn=role_arn, RoleSessionName="cirrus-scan")[
            "Credentials"
        ]
    except botocore.exceptions.ClientError:
        log.exception("assume_role call failed for: %s", role_arn)
        return {}

    creds = {
        "aws_access_key_id": response["AccessKeyId"],
        "aws_secret_access_key": response["SecretAccessKey"],
        "aws_session_token": response["SessionToken"],
    }

    log.info("assume_role call succeeeded for: %s", role_arn)

    return creds


def get_prisma_token():
    """Retrieves Prisma Access key and secret key id from Secret Manager"""
    secret_name = "PrismaAccessKeys"
    region_name = "us-west-2"

    # Get the global audit account
    accounts_bucket = os.getenv("CIRRUS_SCAN_RESULTS_BUCKET")

    if not accounts_bucket:
        log.error("Error in retrieving Global Account bucket details. Exiting!")
        raise SecretManagerRetrievalError
    elif "dev-private" in accounts_bucket:
        auditRoleArn = "arn:aws:iam::878238275157:role/GD-AuditFramework-SecretsManagerReadOnlyRole"
    elif "gd-audit-prod-cirrus-scan-results-p" in accounts_bucket:
        auditRoleArn = "arn:aws:iam::339078146124:role/GD-AuditFramework-SecretsManagerReadOnlyRole"
    elif "gd-audit-prod-cirrus-scan-results-h" in accounts_bucket:
        auditRoleArn = "arn:aws:iam::512827982966:role/GD-AuditFramework-SecretsManagerReadOnlyRole"
    elif "gd-audit-prod-cirrus-scan-results-r" in accounts_bucket:
        auditRoleArn = "arn:aws:iam::906957162968:role/GD-AuditFramework-SecretsManagerReadOnlyRole"
    elif "gd-audit-prod-cirrus-scan-results" in accounts_bucket:
        auditRoleArn = "arn:aws:iam::672751022979:role/GD-AuditFramework-SecretsManagerReadOnlyRole"

    log.info("AuditRoleARN: %s", auditRoleArn)

    # Get tenable API keys from Global Audit account
    creds = assume_role(auditRoleArn)

    if not creds:
        log.error("assume_role call failed")
        raise SecretManagerRetrievalError

    client = boto3.client("secretsmanager", region_name, **creds)

    try:
        # Retieving Tenable API keys
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "DecryptionFailureException":
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise SecretManagerRetrievalError
        elif e.response["Error"]["Code"] == "InternalServiceErrorException":
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise SecretManagerRetrievalError
        elif e.response["Error"]["Code"] == "InvalidParameterException":
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise SecretManagerRetrievalError
        elif e.response["Error"]["Code"] == "InvalidRequestException":
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise SecretManagerRetrievalError
        elif e.response["Error"]["Code"] == "ResourceNotFoundException":
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise SecretManagerRetrievalError
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if "SecretString" in get_secret_value_response:
            secret = get_secret_value_response["SecretString"]
        else:
            decoded_binary_secret = base64.b64decode(
                get_secret_value_response["SecretBinary"]
            )

    secret = json.loads(get_secret_value_response["SecretString"])

    accesskey_dict = json.load(secret)

    if not accesskey_dict:
        log.error("Unable to retrieve access keys")
        raise SecretManagerRetrievalError

    pl = dict()
    pl["password"] = accesskey_dict["id"]
    pl["username"] = accesskey_dict["secretKey"]

    payload = json.dumps(pl)

    # headers = {
    #     "accept": "application/json; charset=UTF-8",
    #     "content-type": "application/json; charset=UTF-8",
    # }

    # url = PRISMA_COMPUTE_REST_API_URL + "/authenticate"
    # response = requests.request("GET", url=url, data=payload, headers=headers)
    response = create_prisma_api_request("GET", url="authenticate", payload=payload)

    logging.debug(
        "get_token: response status_code {}".format(
            response.status_code
        )
    )

    if response.status_code == 200:
        text_json = json.loads(response.text)
        token = text_json["token"]
        return token
    else:
        logging.error("Unable to obtain JWT!")

    return token

def region_has_repos(region):
    """Parse through parameters, and get scan targets"""
    
    ecr_client = boto3.client("ecr", region_name=region)
    repositories = ecr_client.describe_repositories()["repositories"]
    repositories_uris = [repository["repositoryUri"] for repository in repositories]

    return len(repositories_uris) > 0
    

def create_prisma_api_request(req_type,url,token=None,payload=None, params=None):
    """Helper function to make Tenable API requests"""

    # As we may hit Prisma API limits, try hitting Prisma at least 3 times before shutting down Vulnerability Scanner
    retries = Retry(
        total=3,
        status_forcelist={429, 501, 502, 503, 504},
        backoff_factor=1,
        respect_retry_after_header=True,
    )

    headers = None
    if token is not None:
        headers = {"Authorization":"Bearer " + token} 
     

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
        if req_type == "POST":
            response = session.post(fullurl, params=params, data=payload, timeout=5.0)
        else:
            response = session.get(fullurl, params=params, data=payload, timeout=5.0)

        if response.status_code == 200:
            return response
    except:
        log.exception("Exception occurred in making Tenable request")

    log.error(
        "Prisma API call from %s method returning status code: %i.",
        url,
        response.status_code,
    )

    log.error("Prisma API call failed from method: %s. Exiting!", url)
    raise ExitContainerScanner

def force_ecr_registry_scan(token, region, account_id):
    
    # curl -H "Authorization: Bearer "${TOKEN}"" -X POST -d '{"registry":"226955763576.dkr.ecr.us-west-2.amazonaws.com","repository":"","tag":"","cap":5,"os":"linux","hostname":"","namespace":"","useAWSRole":true,"version":"aws","credential":{"_id":"","type":"","accountID":"","accountGUID":"","secret":{"encrypted":""},"apiToken":{"encrypted":""},"lastModified":"0001-01-01T00:00:00Z","owner":"","tokens":null},"credentialID":"","roleArn":"","scanners":1,"versionPattern":""}' https://us-east1.cloud.twistlock.com/us-2-158254964/api/v1/settings/registry
    ecr_registry_name = account_id + ".dkr.ecr." + region + ".amazonaws.com"
    reg = '{"tag":{"registry":""}}'
    reg_json = json.loads(reg)
    reg_json["registry"] = ecr_registry_name
    
    response = create_prisma_api_request("POST", "/registry/scan", token=token, payload=json.dumps(reg_json))

    if response.status_code == 200:
        logging.info("Forced scan of ECR registry %s!", ecr_registry_name )
        return 
    else:
        logging.error("Unable to force scan of ECR registry %s!", ecr_registry_name )

    raise ForceScanError

def register_ecr_registry(token, region, account_id, vpc_id):
    """Register ECR registry with Prisma"""
    log.info("Waiting for Tenable scanner registration")

    # make a call to get the name of the provisioned scanner
    client = boto3.client("ec2")
    response = client.describe_instances(
        Filters=[
            {"Name": "tag:Name", "Values": ["ContainerScanner"]},
            {"Name": "instance-state-name", "Values": ["running"]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ]
    )
    
    try:
        scanner_dnsname = response["Reservations"][0]["Instances"][0]["NetworkInterfaces"][
            0
        ]["PrivateDnsName"]
        log.info("Scanner name : %s" % scanner_dnsname)
    except KeyError:
        log.error("Scanner IP not found")
        scanner_dnsname = None

    if scanner_dnsname:
        # register ECR registry
        # curl -H "Authorization: Bearer "${TOKEN}"" -X POST -d '{"registry":"226955763576.dkr.ecr.us-west-2.amazonaws.com","repository":"","tag":"","cap":5,"os":"linux","hostname":"","namespace":"","useAWSRole":true,"version":"aws","credential":{"_id":"","type":"","accountID":"","accountGUID":"","secret":{"encrypted":""},"apiToken":{"encrypted":""},"lastModified":"0001-01-01T00:00:00Z","owner":"","tokens":null},"credentialID":"","roleArn":"","scanners":1,"versionPattern":""}' https://us-east1.cloud.twistlock.com/us-2-158254964/api/v1/settings/registry
        ecr_registry_name = account_id + ".dkr.ecr." + region + ".amazonaws.com"
        reg = '{"registry":"","repository":"","tag":"","cap":5,"os":"linux","hostname":"","namespace":"","useAWSRole":true,"version":"aws","credential":{"_id":"","type":"","accountID":"","accountGUID":"","secret":{"encrypted":""},"apiToken":{"encrypted":""},"lastModified":"0001-01-01T00:00:00Z","owner":"","tokens":null},"credentialID":"","roleArn":"","scanners":1,"versionPattern":""}'
        reg_json = json.loads(reg)
        reg_json["registry"] = ecr_registry_name
        reg_json["hostname"] = scanner_dnsname
        response = create_prisma_api_request("POST", "settings/registry", token=token, payload=json.dumps(reg_json))

        if response.status_code == 200:
            logging.info("Registered %s with ECR registry %s!", scanner_dnsname, ecr_registry_name )
            return 
        else:
            logging.error("Unable to register %s with ECR registry %s!", scanner_dnsname, ecr_registry_name )

    raise RegistrationError

def wait_for_scan_completion(token,region, account_id):
    """Wait for the scan to be completed"""

    log.info("Waiting for Container Scan to finish")
    # sleep for 30 minutes due to lack of progress api
    time.sleep(30*60)

    # # This loop runs for ~60 minutes, to wait for Prisma scan completion
    # for setup_count in range(60):
    #     log.info("Getting Tenable Scan Status")
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


def retrieve_scanner_results(token, region, account_id):
       
    # https://us-east1.cloud.twistlock.com/us-2-158254964/api/v1/registry/download?registry="226955763576.dkr.ecr.us-east-1.amazonaws.com" 
    ecr_registry_name = account_id + ".dkr.ecr." + region + ".amazonaws.com"
    param = "registry=" + ecr_registry_name
    
    # all results in csv format
    response = create_prisma_api_request("GET", "/registry/download", token=token, params=param)

    if response.status_code == 200:
        logging.info("Retrieve scan results for ECR registry %s.", ecr_registry_name )
        return response.text
    else:
        logging.error("Unable to retrieve scan results for ECR registry %s.", ecr_registry_name )


def evaluate_scanner_results(handle, csv_results):
    """Evaluate scanner results and generate Security Hub findings."""
    log.info("Evaluating Tenable scanner results")

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
                "The Tenable scanner detected an issue (%s)" % description
            )
            overrides["Remediation"] = {"Recommendation": {"Text": solution}}
            overrides["Resources"] = [
                {"Type": "AwsEc2Instance", "Id": host, "Region": handle.aws_region()}
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
                finding = handle.Finding(overrides["Id"], override_dict=overrides)
                finding.save()
            except Exception:
                log.exception("Error while processing scanner result:")

def save_scanner_results(results):
    """Save scanner results to an S3 bucket."""
    log.info("Saving Tenable scanner results")

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
    try:
        s3 = boto3.client("s3")
        s3.upload_file(temp_csv, results_bucket, results_key)
    except botocore.exceptions.ClientError:
        log.exception(
            "put_object failed for: bucket: %s with key: %s",
            results_bucket,
            results_key,
        )

    if os.path.isfile(temp_csv):
        os.remove(temp_csv)

def provisioned_product_exists(provisioned_product_name):
    
    client = boto3.client("servicecatalog")
    
    try:
        response = client.describe_provisioned_product(Name=provisioned_product_name)
    except client.exceptions.ResourceNotFoundException as e:
        return False
    
    return True

def deprovision_scanner(provisioned_product_name):
    """Deprovision a container scanner"""
    log.info("Deprovisioning container scanner")

    # Terminate VulnScanner Service Catalog Product from AWS account
    try:
        client = boto3.client("servicecatalog")
        response = client.terminate_provisioned_product(
            ProvisionedProductName=provisioned_product_name
        )

        log.info("container SC product successfully deleted!")

    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            log.info("ContainerScanner do not exist! No need to deprovision!")
        else:
            log.error("Error in deleting the VulnScanner SC product from AWS account")
            log.error(e.response["Error"]["Message"])

    #wait for deprovisioning to complete
    for setup_count in range(15):
        if not provisioned_product_exists(provisioned_product_name):
            break
        time.sleep(60)
    else:
        log.error("Deprovisioning timed out")        
        raise DeprovisioningScannerTimeoutError      
        
def provision_scanner(provisioned_product_name, vpc_id):
    """Provision a Prisma scanner, using Service Catalog product EC2"""
    log.info("Provisioning Tenable scanner")
    client = boto3.client("servicecatalog")

    # GetProductId
    response = client.search_products(Filters={"FullTextSearch": ["EC2"]})
    product_id = response["ProductViewSummaries"][0]["ProductId"]

    # Get other product details
    response = client.describe_product(Id=product_id)

    for provision_artifact in response["ProvisioningArtifacts"]:
        if provision_artifact["Name"] == SC_EC2_VERSION:
            provisioning_artifact_id = provision_artifact["Id"]

    # Get public subnet
    ec2 = boto3.client("ec2")
    response = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]},])

    has_public_subnet_id = False
    for subnet in response["Subnets"]:
        if subnet["AvailableIpAddressCount"] > 4:
            for tag in subnet["Tags"]:
                if tag["Key"] == "Name":
                    if "public" in tag["Value"]:
                        subnet_id = subnet["SubnetId"]
                        has_public_subnet_id = True
                        break
        if has_public_subnet_id:
            break

    # Exit gracefully if no public subnet is present
    if not has_public_subnet_id:
        log.info("No public subnet in VPC %s. Exiting!", vpc_id)
        raise ExitVulnScanner

    log.debug("VPC ID: %s", vpc_id)
    log.debug("Subnet Id: %s", subnet_id)
    # provisioned_product_name = "VulnScanner-" + vpc_id

    # Provision VulnScanner Service Catalog Product
    response = client.provision_product(
        ProductId=product_id,
        ProvisionedProductName=provisioned_product_name,
        ProvisioningArtifactId=provisioning_artifact_id,
        Tags=[{"Key": "doNotShutDown", "Value": "true"}],
        ProvisioningParameters=[
            {"Key": "VPCSubnetId", "Value": subnet_id},
            {"Key": "TenableAPIKey", "Value": linking_key},
            {"Key": "VPCId", "Value": vpc_id},
        ],
    )

    provisioned_product_id = response["RecordDetail"]["ProvisionedProductId"]
    log.info("Provisioned Product ID: %s", provisioned_product_id)

    # Wait for product to be provisioned
    for setup_count in range(15):
        response = client.describe_provisioned_product(Id=provisioned_product_id)
        if response["ProvisionedProductDetail"]["Status"] == "AVAILABLE":
            log.info("Vulnerability Scanner successfully provisioned")
            break
        time.sleep(60)
    else:
        log.error("Provisioning timed out")
        log.error(response)
        raise ProvisioningTimeoutError
    return provisioned_product_name

def generate_informational_finding(handle):
    """Generate an informational finding indicating test is complete"""

    log.debug("Test complete")
    utcnow = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Generate a Security Hub finding
    finding_id = "vulnscan/complete/%s/%s" % (handle.aws_region(), vpc_id)
    finding = handle.Finding(finding_id)

    finding.ProductFields["Environment"] = os.getenv(
        "CIRRUS_SCAN_ACCOUNT_ENVIRONMENT", "UNKNOWN"
    )
    finding.ProductFields["TaskUuid"] = os.getenv("CIRRUS_SCAN_TASK_UUID", "UNKNOWN")
    finding.ProductFields["TeamName"] = os.getenv(
        "CIRRUS_SCAN_ACCOUNT_TEAM_NAME", "UNKNOWN"
    )

    finding.Title = "Vulnscan: [%s, %s] finished at %s" % (
        handle.aws_region(),
        vpc_id,
        utcnow,
    )
    finding.Compliance = {"Status": "PASSED"}
    finding.Description = "No description available."
    finding.GeneratorId = "Vulnscan"
    finding.LastObservedAt = utcnow

    finding.save()

 def update_ssm_state_parameter(self, value):
        """Update shared instance state in Parameter Store"""

        self.ssm.put_parameter(
            Name=self.state_parameter, Value=value, Overwrite=True,
        )

        log.debug("Updated %s: %s", self.state_parameter, value)
        return value

    def get_ssm_state_parameter(self):
        """Obtain current shared instance state from Parameter Store"""

        try:

            response = self.ssm.get_parameter(Name=self.state_parameter)

        except ClientError as e:
            if e.response["Error"]["Code"] == "ParameterNotFound":
                log.debug("%s : Not found", self.state_parameter)
                return None
            raise

        if not response["Parameter"]:
            return None

        log.debug("%s : %s", self.state_parameter, response["Parameter"]["Value"])
        return response["Parameter"]["Value"]

    # High-level locking methods used by caller; these should be the only two
    # public methods (other than the constructor itself).

    def lock(self, task_uuid):
        """Register interest in shared tenable scanner instance, possibly creating it"""
        # creates task parameter
        self.create_ssm_task_parameter(task_uuid)

        # transition to operational state; this either succeeds or raises an
        # exception (which we do not attempt to catch), so we unconditionally
        # return the UUID.
        self.state_change("OPERATIONAL")
        return task_uuid

    def unlock(self, task_uuid):
        """Release shared tenable scanner instance, possibly deprovisioning it"""

        self.delete_ssm_task_parameter(task_uuid)

        # check if any other task in the VPC is using VulnScanner
        if self.is_any_task_running():
            log.debug("More scans in progress. Not terminating VulnScanner")
            return

        # Terminate VulnScanner
        log.debug("Terminating VulnScanner!")
        self.state_change("DEPROVISIONING")

    # Low-level routines used for marking locks using Parameter Store, where
    # they are visible to cooperating processes.

    def create_ssm_task_parameter(self, task_uuid):
        """Create persistent lock marker in Parameter Store"""

        expiration_time = datetime.datetime.now() + self.timeout

        name = self.task_state_path + task_uuid

        self.ssm.put_parameter(
            Name=name,
            Description="Vulnerability Scan Active Task",
            Value=str(expiration_time),
            Type="String",
            Tier="Standard",
        )

        log.debug("SSM task parameter created: %s", name)

    def delete_ssm_task_parameter(self, task_uuid):
        """Remove persistent lock marker in Parameter Store"""

        name = self.task_state_path + task_uuid

        self.ssm.delete_parameter(Name=name)

        log.debug("SSM task parameter deleted: %s", name)

    def is_any_task_running(self):
        """Returns True if unexpired lock markers exist in Parameter Store"""

        response = self.ssm.get_parameters_by_path(
            Path=self.task_state_path[:-1], Recursive=True
        )
        log.debug("Check if any more scans in progress.")
        # check if Response is empty
        if not response["Parameters"]:
            return False
        else:
            for parameter in response["Parameters"]:
                expiration_time = parameter["Value"]
                if str(datetime.datetime.now()) < str(expiration_time):
                    log.debug("is_vulnerability_scan_task_running? : YES")
                    return True

        log.debug("is_vulnerability_scan_task_running? : NO")
        return False

 def update_ssm_state_parameter(self, value):
        """Update shared instance state in Parameter Store"""

        self.ssm.put_parameter(
            Name=self.state_parameter, Value=value, Overwrite=True,
        )

        log.debug("Updated %s: %s", self.state_parameter, value)
        return value

    def get_ssm_state_parameter(self):
        """Obtain current shared instance state from Parameter Store"""

        try:

            response = self.ssm.get_parameter(Name=self.state_parameter)

        except ClientError as e:
            if e.response["Error"]["Code"] == "ParameterNotFound":
                log.debug("%s : Not found", self.state_parameter)
                return None
            raise

        if not response["Parameter"]:
            return None

        log.debug("%s : %s", self.state_parameter, response["Parameter"]["Value"])
        return response["Parameter"]["Value"]

    # High-level locking methods used by caller; these should be the only two
    # public methods (other than the constructor itself).

    def lock(self, task_uuid):
        """Register interest in shared tenable scanner instance, possibly creating it"""
        # creates task parameter
        self.create_ssm_task_parameter(task_uuid)

        # transition to operational state; this either succeeds or raises an
        # exception (which we do not attempt to catch), so we unconditionally
        # return the UUID.
        self.state_change("OPERATIONAL")
        return task_uuid

    def unlock(self, task_uuid):
        """Release shared tenable scanner instance, possibly deprovisioning it"""

        self.delete_ssm_task_parameter(task_uuid)

        # check if any other task in the VPC is using VulnScanner
        if self.is_any_task_running():
            log.debug("More scans in progress. Not terminating VulnScanner")
            return

        # Terminate VulnScanner
        log.debug("Terminating VulnScanner!")
        self.state_change("DEPROVISIONING")

    # Low-level routines used for marking locks using Parameter Store, where
    # they are visible to cooperating processes.

    def create_ssm_task_parameter(self, task_uuid):
        """Create persistent lock marker in Parameter Store"""

        expiration_time = datetime.datetime.now() + self.timeout

        name = self.task_state_path + task_uuid

        self.ssm.put_parameter(
            Name=name,
            Description="Vulnerability Scan Active Task",
            Value=str(expiration_time),
            Type="String",
            Tier="Standard",
        )

        log.debug("SSM task parameter created: %s", name)

    def delete_ssm_task_parameter(self, task_uuid):
        """Remove persistent lock marker in Parameter Store"""

        name = self.task_state_path + task_uuid

        self.ssm.delete_parameter(Name=name)

        log.debug("SSM task parameter deleted: %s", name)

    def is_any_task_running(self):
        """Returns True if unexpired lock markers exist in Parameter Store"""

        response = self.ssm.get_parameters_by_path(
            Path=self.task_state_path[:-1], Recursive=True
        )
        log.debug("Check if any more scans in progress.")
        # check if Response is empty
        if not response["Parameters"]:
            return False
        else:
            for parameter in response["Parameters"]:
                expiration_time = parameter["Value"]
                if str(datetime.datetime.now()) < str(expiration_time):
                    log.debug("is_vulnerability_scan_task_running? : YES")
                    return True

        log.debug("is_vulnerability_scan_task_running? : NO")
        return False

def create_ssm_task_parameter(ssm, task_name):
        """Create persistent lock marker in Parameter Store"""

        expiration_time = datetime.datetime.now() + datetime.timedelta(hours=1)
        
        ssm.put_parameter(
            Name=task_name,
            Description="Container Scan Active Task",
            Value=str(expiration_time),
            Type="String",
            Tier="Standard",
            Overwrite=True,
        )

        log.debug("SSM task parameter created: %s", task_name)

def delete_ssm_task_parameter(ssm, task_name):
        """Remove persistent lock marker in Parameter Store"""
       
        ssm.delete_parameter(Name=task_name)

        log.debug("SSM task parameter deleted: %s", task_name)

def get_ssm_task_parameter(ssm, task_name):
        """Obtain task parameter from Parameter Store"""

        try:

            response = ssm.get_parameter(Name=task_name)

        except ClientError as e:
            if e.response["Error"]["Code"] == "ParameterNotFound":
                log.debug("%s : Not found", task_name)
                return None
            raise

        if not response["Parameter"]:
            return None

        log.debug("%s : %s", task_name, response["Parameter"]["Value"])
        return response["Parameter"]["Value"]

if __name__ == "__main__":
    # Adjust log format if running on a terminal
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s"
    )

    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.INFO)
    logging.getLogger("urllib3").setLevel(logging.CRITICAL)
    scanner_id = ""
    exception_rules = wrapper.get_exception_rules()
    context = common.securityhub.SecurityHub_Manager(exception_rules=exception_rules)
    results = ""
    scanner = ""
    scanner_details = None
    lock_id = None
    

    try:
       
        token = get_prisma_token()
        parameters = wrapper.get_parameters()
        task_uuid = os.getenv("CIRRUS_SCAN_TASK_UUID", "UNDEFINED")
        # store script parameter in parameter table?
        # sh_parameters = parameters.get("sh_params")
        vpc_id = parameters["vpc_id"]
        region = boto3.session.Session().region_name
        account_id = boto3.client("sts").get_caller_identity().get("Account")
        provisioned_product_name = "ContainerScanner-" + vpc_id

        # isProvisioned = provisioned_product_exists(provisioned_product_name)

        regionHasRepo = region_has_repos(region)
        
        ssm = boto3.client("ssm")
        task_name = "/CirrusScan/containerscan/" + vpc_id + "/users/" + task_uuid 
        isProvisioned = False if get_ssm_task_parameter(ssm, task_name) is None else True
    
        # do scan only when there's repo
        if not isProvisioned and regionHasRepo:
        # launch EC2 through service catalog with user data
        # - register ECR registry in Prisma with hostname
        # - force repo scan
        # - poll repo scan progress
        # - when complete, get repo scan details, use pagination
        # generate findings for security hub
            # add state parameter
            
            create_ssm_task_parameter(ssm, task_name)
        

            instance = tenable_instance.TenableInstance(
                vpc_id, provision_scanner, deprovision_scanner
            )

            
            # Lock the current task with Tenable instance
            lock_id = instance.lock(os.getenv("CIRRUS_SCAN_TASK_UUID"))

            register_ecr_registry(token,region, account_id, vpc_id)

            force_ecr_registry_scan(token, region, account_id)
           
            wait_for_scan_completion(token, region, account_id)

            results = retrieve_scanner_results(token, region, account_id)

            save_scanner_results(results)

        context.begin_transaction(
            scope_prefix="containerscan/" + context.aws_region(),
            scope_region=context.aws_region(),
        )

        if results:
            evaluate_scanner_results(context, results)

       
        generate_informational_finding(context)
        context.end_transaction(autoarchive=True, dont_archive=None)

        # Pass back finding demographic information. For purposes
        # of this scanner, any finding with a normalized severity
        # of at least 70 constitutes a compliance failure.
        scan_info = context.get_finding_data()
        compliance = "PASS"
        for severity in scan_info["severity"]:
            if severity >= 70:
                compliance = "FAIL"
                break
        wrapper.put_status(
            {"status": "SUCCESS", "compliance": compliance, "finding_data": scan_info}
        )
       
        deprovision_scanner(provisioned_product_name)
        delete_ssm_task_parameter(ssm, task_name)

    except ExitContainerScanner:
        log.info("Exiting Container scanner!")
    except:
        log.exception("Error while executing vulnerability scanner")
    
        