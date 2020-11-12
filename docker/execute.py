#!/usr/bin/env python3

import datetime
import logging
import os
import boto3
import wrapper
from common import securityhub
from aws_clients import SecurityTokenServiceClient, EC2Client, ECRClient, SSMClient, SecretsManagerClient, S3Client, ServiceCatalog
from prisma import Scanner, PrismaClient
from errors import SecretManagerRetrievalError, ExitContainerScanner

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def get_audit_role_arn(ssm):
    """Get audit role ARN based on an account bucket"""
    orgType = ssm.get_org_type()
    auditAccount = "672751022979"
    if orgType == "pci":
        auditAccount = "339078146124"
    elif orgType == "registry":
        auditAccount = "906957162968"

    auditRoleArn = "arn:aws:iam::"+auditAccount + \
        ":role/GD-AuditFramework-SecretsManagerReadOnlyRole"

    # accounts_bucket = os.getenv("CIRRUS_SCAN_RESULTS_BUCKET")

    # if not accounts_bucket:
    #     logger.error("Error in retrieving Global Account bucket details. Exiting!")
    #     raise SecretManagerRetrievalError
    # elif "dev-private" in accounts_bucket:
    #     auditRoleArn = "arn:aws:iam::878238275157:role/GD-AuditFramework-SecretsManagerReadOnlyRole"
    # elif "gd-audit-prod-cirrus-scan-results-p" in accounts_bucket:
    #     auditRoleArn = "arn:aws:iam::339078146124:role/GD-AuditFramework-SecretsManagerReadOnlyRole"
    # elif "gd-audit-prod-cirrus-scan-results-h" in accounts_bucket:
    #     auditRoleArn = "arn:aws:iam::512827982966:role/GD-AuditFramework-SecretsManagerReadOnlyRole"
    # elif "gd-audit-prod-cirrus-scan-results-r" in accounts_bucket:
    #     auditRoleArn = "arn:aws:iam::906957162968:role/GD-AuditFramework-SecretsManagerReadOnlyRole"
    # elif "gd-audit-prod-cirrus-scan-results" in accounts_bucket:
    #     auditRoleArn = "arn:aws:iam::672751022979:role/GD-AuditFramework-SecretsManagerReadOnlyRole"

    logger.info("AuditRoleARN: %s", auditRoleArn)
    return auditRoleArn


def main():
    """Main entry point for ContainerScanner logic"""
    results = None
    region = boto3.session.Session().region_name
    logger.debug("region: %s", region)

    s3_client = S3Client(logger)
    sc_client = ServiceCatalog(logger)
    sts_client = SecurityTokenServiceClient(logger)
    sm_client = SecretsManagerClient(logger)
    ssm_client = SSMClient(logger)
    ecr_client = ECRClient(logger)
    ec2_client = EC2Client(logger)

    audit_role_arn = get_audit_role_arn(ssm_client)
    # vpc_id = wrapper.get_parameters()["vpc_id"]
    vpc_id = ssm_client.get_vpc_id()

    task_uuid = os.getenv("CIRRUS_SCAN_TASK_UUID", "UNDEFINED")
    task_name = f"/CirrusScan/containerscan/{vpc_id}/{task_uuid}"
    provisioned_product_name = f"ContainerScanner-{vpc_id}"

    prisma_client = PrismaClient(logger, sts_client, sm_client, ec2_client)
    prisma_scanner = Scanner(logger, s3_client, sc_client,
                             ssm_client, provisioned_product_name, task_name)

    isProvisioned = ssm_client.has_task_parameter(task_name)
    logger.debug("isProvisioned: %s", isProvisioned)

    sendToSecurityHub = True

    if not isProvisioned and ecr_client.has_repositories(region):
        # launch EC2 through service catalog with user data
        # - register ECR registry in Prisma with hostname
        # - force repo scan
        # - poll repo scan progress
        # - when complete, get repo scan details, use pagination
        # generate findings for security hub

        prisma_token = prisma_client.get_token(audit_role_arn)

        account_id = sts_client.get_account_id()
        ecr_registry_name = f"{account_id}.dkr.ecr.{region}.amazonaws.com"
        logger.debug("ecr_registry_name: %s", ecr_registry_name)
        subnet_id = ec2_client.get_subnet_id(vpc_id)
        logger.debug("subnet_id: %s", subnet_id)
        ssm_client.create_task_parameter(task_name)

        sc_client.provision_scanner(
            vpc_id, subnet_id, provisioned_product_name)

        prisma_client.register_ecr_registry(
            prisma_token, ecr_registry_name, vpc_id)

        prisma_client.force_ecr_registry_scan(prisma_token, ecr_registry_name)

        prisma_client.wait_for_scan_completion()

        results = prisma_client.retrieve_scanner_results(
            prisma_token, ecr_registry_name)

        prisma_scanner.save_scanner_results(results)

        if sendToSecurityHub:
            security_hub_mgr = securityhub.SecurityHub_Manager(
                exception_rules=wrapper.get_exception_rules())

            security_hub_mgr.begin_transaction(
                scope_prefix="containerscan/" + security_hub_mgr.aws_region(),
                scope_region=security_hub_mgr.aws_region(),
            )

            if results is not None:
                prisma_scanner.evaluate_scanner_results(
                    security_hub_mgr, results)

            prisma_scanner.generate_informational_finding(security_hub_mgr)
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

    return prisma_scanner


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s"
    )

    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.INFO)
    logging.getLogger("urllib3").setLevel(logging.CRITICAL)
    prisma_scanner = None

    try:
        prisma_scanner = main()
    except ExitContainerScanner:
        logger.info("Exiting Container scanner!")
    except:
        logger.exception("Error while executing containerscan scanner")
    finally:
        if prisma_scanner is not None:            
            prisma_scanner.remove()
