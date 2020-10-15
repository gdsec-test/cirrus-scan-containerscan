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
SC_EC2_VERSION = "1.0.11"

PRISMA_COMPUTE_REST_API_URL = "https://us-east1.cloud.twistlock.com/us-2-158254964/api/v1/"

class ProvisioningTimeoutError(Exception):
    """Provision operation timed out"""

    pass


class RegistrationTimeoutError(Exception):
    """Provision operation timed out"""

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
    """One of the resources required to run VulnScanner is missing. Exiting!"""

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


def getPrismaToken():
    """Retrieves Tenable API keys from Secret Manager"""
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
    
    client = boto3.client("ecr", region_name=region)

    response = client.describe_repositories()
    
    return len(response["repositories"])>0


def provision_scanner(vpc_id):
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
    provisioned_product_name = "VulnScanner-" + vpc_id

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


def wait_for_scanner_registration(vpc_id):
    """Wait for the provisioned scanner to be registered with Tenable."""
    log.info("Waiting for Tenable scanner registration")

    # make a call to get the name of the provisioned scanner
    headers = tenable_keys["headers"]
    client = boto3.client("ec2")
    response = client.describe_instances(
        Filters=[
            {"Name": "tag:Name", "Values": ["TenableScanner"]},
            {"Name": "instance-state-name", "Values": ["running"]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ]
    )

    region = boto3.session.Session().region_name
    account_id = boto3.client("sts").get_caller_identity().get("Account")
    scanner_name = "cirrusscan" + "-" + account_id + "-" + region + "-" + vpc_id

    try:
        scanner_ip = response["Reservations"][0]["Instances"][0]["NetworkInterfaces"][
            0
        ]["PrivateIpAddress"]
        log.info("Scanner name : %s" % scanner_name)
    except KeyError:
        log.error("Scanner IP not found")
        scanner_ip = None

    url = "https://cloud.tenable.com/scanners"

    # Wait for ~30 minutes for the EC2 nessus scanner to get registered with Tenable cloud platform
    # This is needed to kick off Tenable scans
    for setup_count in range(30):
        log.info("Waiting for Tenable Scanner to get registered")
        time.sleep(60)
        response = create_tenable_api_request(
            "wait_for_scanner_registration", "GET", url, headers
        )
        scanners = json.loads(response.text)

        for scanner in scanners["scanners"]:
            if scanner["name"] == scanner_name:
                scanner_id = scanner["id"]
                status = scanner["status"]
                if status == "on":
                    log.info(
                        "Scanner: %s is successfully registered with Tenable",
                        scanner_name,
                    )
                    return {"scanner_id": scanner_id, "scanner_ip": scanner_ip}

    log.error("Registration timed out")
    raise RegistrationTimeoutError


def create_scan(headers, scanner_id, vpc_id, targets):
    """Create a new scan."""
    log.info("Creating a new scan in Tenable.io")

    # Create a new scan in Tenable with received AWS targets
    scan_template_uuid = TENABLE_SCAN_TEMPLATE

    region = boto3.session.Session().region_name
    account_id = boto3.client("sts").get_caller_identity().get("Account")
    scan_name = account_id + "-" + region + "-" + vpc_id + "-cirrusscan"

    data = {
        "uuid": scan_template_uuid,
        "settings": {
            "name": scan_name,
            "enabled": True,
            "policy_id": TENABLE_POLICY_ID,
            "scanner_id": scanner_id,
            "text_targets": targets,
        },
    }

    payload = json.dumps(data)
    url = "https://cloud.tenable.com/scans"

    response = create_tenable_api_request(
        "create_scan", "POST", url, headers, payload=payload
    )
    response = json.loads(response.text)
    scanId = response["scan"]["id"]
    return scanId


def run_scanner(headers, scanId):
    """Invoke a scan using the Tenable API."""
    log.info("Scheduling Tenable scanner execution")
    url = "https://cloud.tenable.com/scans/" + str(scanId) + "/launch"

    create_tenable_api_request("run_scanner", "POST", url, headers)


def wait_for_scan_completion(token,registry):
    """Wait for the scan to be completed"""

    log.info("Waiting for Container Scan to finish")
    
    # This loop runs for ~60 minutes, to wait for Prisma scan completion
    for setup_count in range(60):
        log.info("Getting Tenable Scan Status")
        time.sleep(60)
        
        offset = 1
        limit = 50
        params ={"limit":limit,"offset":offset}

        while True:
            response = create_prisma_api_request("GET", "registry/progress", token=token, params=params)
            data = json.loads(response.text)
           
            for x in data['registry']:
                ## registry still being scanned
                if(x == registry): 
                    break;

            if len(data) < limit:
                ## at this point, we have exhaused the list and didnt find the one, meaning it is done.
                return;    
            #continue with next page
            offset += limit     

    log.error("Scanning timed out")
    raise ScanningTimeoutError


def retrieve_scanner_results(headers, scanId):
    """Retrieve Tenable scanner results."""
    log.info("Retrieving Tenable scan results")

    # API call to request export from tenable.io
    url = "https://cloud.tenable.com/scans/" + str(scanId) + "/export"

    payload = {"format": "csv", "chapters": "vuln_by_host"}
    payload = json.dumps(payload)

    response = create_tenable_api_request(
        "retrieve_scanner_results", "POST", url, headers, payload=payload
    )
    response = json.loads(response.text)

    # API Call to check scan export status
    file_name = response["file"]
    url = (
        "https://cloud.tenable.com/scans/"
        + str(scanId)
        + "/export/"
        + file_name
        + "/status"
    )

    # This loop waits for about 10 minutes for the Tenable CSV report export status to go READY
    for setup_count in range(10):
        log.info("Waiting for export status to go READY")

        time.sleep(60)
        response = create_tenable_api_request(
            "retrieve_scanner_results", "GET", url, headers
        )
        response = json.loads(response.text)
        if response["status"] == "ready":
            break
    else:
        log.error("Error in getting scan export status")
        raise ScanningTimeoutError

    url = (
        "https://cloud.tenable.com/scans/"
        + str(scanId)
        + "/export/"
        + file_name
        + "/download"
    )

    response = create_tenable_api_request(
        "retrieve_scanner_results", "GET", url, headers
    )
    return response.text


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
    results_key = "vulnscan/%s/results.csv" % task_uuid

    csv_results = csv.reader(results.split("\r\n"), delimiter=",")

    temp_csv = "/tmp/results.csv"
    vuln_results_csv = open(temp_csv, "w")
    csv_writer = csv.writer(vuln_results_csv)

    for result in csv_results:
        csv_row = result
        csv_writer.writerow(csv_row)

    vuln_results_csv.close()
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


def deprovision_scanner(provisioned_product_name):
    """Deprovision a Tenable scanner, using CloudFront, Service Catalog, EC2, etc."""
    log.info("Deprovisioning Tenable scanner")

    headers = tenable_keys["headers"]

    # Terminate VulnScanner Service Catalog Product from AWS account
    try:
        client = boto3.client("servicecatalog")
        response = client.terminate_provisioned_product(
            ProvisionedProductName=provisioned_product_name
        )

        log.info("VulnScanner SC product successfully deleted!")

    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            log.info("VulnScanner do not exist! No need to deprovision!")
        else:
            log.error("Error in deleting the VulnScanner SC product from AWS account")
            log.error(e.response["Error"]["Message"])

    # Terminate Scanner from Tenable.io
    if scanner_details and "scanner_id" in scanner_details:
        scanner_id = scanner_details["scanner_id"]
        try:
            url = "https://cloud.tenable.com/scanners/" + str(scanner_id)
            response = create_tenable_api_request(
                "deprovision_scanner", "DELETE", url, headers
            )
            log.info("Scanner successfully de-registered from Tenable cloud!")
        except:
            log.error("Unable to de-register scanner from Tenable cloud")


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


def get_finding_ids_of_stopped_instances(handle, do_not_archive):
    """Get regular expression for all stopped instances"""

    client = boto3.client("ec2")
    running_instances = client.describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
    )

    for reservation in running_instances["Reservations"]:
        for instance in reservation["Instances"]:
            for networkInterface in instance["NetworkInterfaces"]:
                do_not_archive_reg_expression = create_do_not_archive_expression(
                    handle, networkInterface["PrivateIpAddress"]
                )

                do_not_archive.append(do_not_archive_reg_expression)

    log.info("Do not archive list: %s", do_not_archive)

    if not do_not_archive:
        log.debug("No stopped instances in this account!!!")

    return do_not_archive


def create_do_not_archive_expression(handle, ip_address):
    """Returns a regular expression to identify all the findings for a given IP address"""

    reg_expression = (
        r"^vulnscan/" + handle.aws_region() + "/" + vpc_id + "/" + ip_address + "/"
    )
    return reg_expression


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
       
        token = getPrismaToken()

        parameters = wrapper.get_parameters()
        # store script parameter in parameter table?
        # sh_parameters = parameters.get("sh_params")

        region = boto3.session.Session().region_name
        account_id = boto3.client("sts").get_caller_identity().get("Account")

        hasRepo = region_has_repos(region)
        
        # do scan if there's repo
        if hasRepo:
        # launch EC2 through service catalog
        # figure out way to pass in user data
        # force repo scan
        # poll repo scan progress
        # when complete, get repo scan details, use pagination
        # generate findings for security hub

            # Create TenableInstance object
            instance = tenable_instance.TenableInstance(
                vpc_id, provision_scanner, deprovision_scanner
            )

            # Lock the current task with Tenable instance
            lock_id = instance.lock(os.getenv("CIRRUS_SCAN_TASK_UUID"))

            scanner_details = wait_for_scanner_registration(vpc_id)

            scanId = create_scan(
                tenable_keys["headers"], scanner_details["scanner_id"], vpc_id, targets
            )
            run_scanner(tenable_keys["headers"], scanId)

            wait_for_scan_completion(token, registry)

            results = retrieve_scanner_results(tenable_keys["headers"], scanId)

            # save_scanner_results(results)

        context.begin_transaction(
            scope_prefix="containerscan/" + context.aws_region(),
            scope_region=context.aws_region(),
        )

        if results:
            evaluate_scanner_results(context, results)

        # Stopped EC2 instances are not part of current vulnerability scan. Any previously created
        # findings for these instances may still be legit and thus will not be auto-archived.
        do_not_archive_list = get_finding_ids_of_stopped_instances(
            context, do_not_archive_list
        )
        generate_informational_finding(context)
        context.end_transaction(autoarchive=True, dont_archive=do_not_archive_list)

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
    except ExitContainerScanner:
        log.info("Exiting Container scanner!")
    except:
        log.exception("Error while executing vulnerability scanner")
    finally:
        if lock_id:
            instance.unlock(lock_id)
        else:
            log.info("No resources to terminate. VulnScanner exiting!")
