#!/usr/bin/env python3

import datetime
import logging
import os
import boto3
from . import wrapper
from .common import securityhub
from .aws_clients import SecurityTokenServiceClient, EC2Client, ServiceCatalog, ECRClient, SSMClient
from .prisma import Scanner, PrismaClient
from .errors import SecretManagerRetrievalError, ExitContainerScanner

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

CIRRUS_SCAN_BUCKET_ENV_NAME = "CIRRUS_SCAN_RESULTS_BUCKET"


def generate_informational_finding(handle):
    """Generate an informational finding indicating test is complete"""

    logger.debug("Test complete")
    utcnow = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Generate a Security Hub finding
    finding_id = "vulnscan/complete/%s/%s" % (handle.aws_region(), vpc_id)
    finding = handle.Finding(finding_id)

    finding.ProductFields["Environment"] = os.getenv(
        "CIRRUS_SCAN_ACCOUNT_ENVIRONMENT", "UNKNOWN"
    )
    finding.ProductFields["TaskUuid"] = os.getenv(
        "CIRRUS_SCAN_TASK_UUID", "UNKNOWN")
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


def get_accounts_bucket():
    """Get the global audit accounts bucket"""
    accounts_bucket = os.getenv(CIRRUS_SCAN_BUCKET_ENV_NAME)
    if not accounts_bucket:
        logger.error(
            "Error in retrieving Global Account bucket details. Exiting!")
        raise SecretManagerRetrievalError

    return accounts_bucket


def get_audit_role_arn(accounts_bucket):
    """Get audit role ARN based on an account bucket"""
    auditRoleArn = None

    if "dev-private" in accounts_bucket:
        auditRoleArn = "arn:aws:iam::878238275157:role/GDAuditFrameworkContainerScanRole"
    elif "gd-audit-prod-cirrus-scan-results-p" in accounts_bucket:
        auditRoleArn = "arn:aws:iam::339078146124:role/GDAuditFrameworkContainerScanRole"
    elif "gd-audit-prod-cirrus-scan-results-h" in accounts_bucket:
        auditRoleArn = "arn:aws:iam::512827982966:role/GDAuditFrameworkContainerScanRole"
    elif "gd-audit-prod-cirrus-scan-results-r" in accounts_bucket:
        auditRoleArn = "arn:aws:iam::906957162968:role/GDAuditFrameworkContainerScanRole"
    elif "gd-audit-prod-cirrus-scan-results" in accounts_bucket:
        auditRoleArn = "arn:aws:iam::672751022979:role/GDAuditFrameworkContainerScanRole"

    if auditRoleArn is None:
        logger.error("Error in retrieving auditRoleArn. Exiting!")
        raise SecretManagerRetrievalError

    logger.info("AuditRoleARN: %s", auditRoleArn)

    return auditRoleArn


def init_logger():
    """Initialize logger instance"""
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s"
    )

    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.INFO)
    logging.getLogger("urllib3").setLevel(logging.CRITICAL)


if __name__ == "__main__":
    init_logger()

    exception_rules = wrapper.get_exception_rules()
    security_hub_mgr = securityhub.SecurityHub_Manager(
        exception_rules=exception_rules)
    parameters = wrapper.get_parameters()
    vpc_id = parameters["vpc_id"]

    try:
        results = None
        region = boto3.session.Session().region_name
        sts_client = SecurityTokenServiceClient(logger)
        ssm_client = SSMClient(logger)
        ecr_client = ECRClient(region)
        prisma_client = PrismaClient(logger)
        prisma_scanner = Scanner(logger)

        audit_role_arn = get_audit_role_arn(get_accounts_bucket())

        token = prisma_client.get_token(audit_role_arn)

        account_id = sts_client.get_account_id()

        task_uuid = os.getenv("CIRRUS_SCAN_TASK_UUID", "UNDEFINED")
        task_name = "/CirrusScan/containerscan/" + vpc_id + "/" + task_uuid
        isProvisioned = ssm_client.get_task_parameter(
            task_name) is not None
        provisioned_product_name = "ContainerScanner-" + vpc_id

        # do scan only when there's repo
        if not isProvisioned and ecr_client.does_repository_have_repos():
            # launch EC2 through service catalog with user data
            # - register ECR registry in Prisma with hostname
            # - force repo scan
            # - poll repo scan progress
            # - when complete, get repo scan details, use pagination
            # generate findings for security hub

            ssm_client.create_task_parameter(task_name)

            prisma_scanner.provision_scanner(provisioned_product_name, vpc_id)

            ecr_registry_name = account_id + ".dkr.ecr." + region + ".amazonaws.com"

            prisma_scanner.register_ecr_registry(
                token, ecr_registry_name, vpc_id)

            prisma_scanner.force_ecr_registry_scan(token, ecr_registry_name)

            prisma_scanner.wait_for_scan_completion()

            results = prisma_scanner.retrieve_scanner_results(
                token, ecr_registry_name)

            prisma_scanner.save_scanner_results(results)

            security_hub_mgr.begin_transaction(
                scope_prefix="containerscan/" + security_hub_mgr.aws_region(),
                scope_region=security_hub_mgr.aws_region(),
            )

            if results is not None:
                prisma_scanner.evaluate_scanner_results(
                    vpc_id, security_hub_mgr, results)

            generate_informational_finding(security_hub_mgr)
            security_hub_mgr.end_transaction(
                autoarchive=True, dont_archive=None)

            # Pass back finding demographic information. For purposes
            # of this scanner, any finding with a normalized severity
            # of at least 70 constitutes a compliance failure.
            scan_info = security_hub_mgr.get_finding_data()
            compliance = "PASS"
            for severity in scan_info["severity"]:
                if severity >= 70:
                    compliance = "FAIL"
                    break
            wrapper.put_status(
                {"status": "SUCCESS", "compliance": compliance,
                    "finding_data": scan_info}
            )

            prisma_scanner.deprovision_scanner(provisioned_product_name)
            ssm_client.delete_task_parameter(task_name)
    except ExitContainerScanner:
        logger.info("Exiting Container scanner!")
    except:
        logger.exception("Error while executing vulnerability scanner")
