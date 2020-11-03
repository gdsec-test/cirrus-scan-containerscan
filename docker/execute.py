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
import wrapper
from .aws_clients import SecurityTokenServiceClient, EC2Client, ServiceCatalog, ECRClient, SSMClient
from .prisma import Scanner, Prisma
from .errors import ExitContainerScanner
from .utils import initialize_logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# TODO: add function to security hub class
def initialize_security_hub():
    exception_rules = wrapper.get_exception_rules()
    return common.securityhub.SecurityHub_Manager(
        exception_rules=exception_rules)


# TODO: add function to security hub class
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

if __name__ == "__main__":
    initialize_logging()
    security_hub_context = initialize_security_hub()

    results = None
    lock_id = None

    try:
        parameters = wrapper.get_parameters()
        vpc_id = parameters["vpc_id"]

        prisma = Prisma(logger)
        prisma_scanner = Scanner(logger)
        sts_client = SecurityTokenServiceClient(logger)
        ssm_client = SSMClient(logger)

        region = boto3.session.Session().region_name
        ecr_client = ECRClient(region)
        
        token = prisma.get_token()

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

            security_hub_context.begin_transaction(
                scope_prefix="containerscan/" + security_hub_context.aws_region(),
                scope_region=security_hub_context.aws_region(),
            )

            if results is not None:
                prisma_scanner.evaluate_scanner_results(
                    vpc_id, security_hub_context, results)

            generate_informational_finding(security_hub_context)
            security_hub_context.end_transaction(
                autoarchive=True, dont_archive=None)

            # Pass back finding demographic information. For purposes
            # of this scanner, any finding with a normalized severity
            # of at least 70 constitutes a compliance failure.
            scan_info = security_hub_context.get_finding_data()
            compliance = "PASS"
            for severity in scan_info["severity"]:
                if severity >= 70:
                    compliance = "FAIL"
                    break
            wrapper.put_status(
                {"status": "SUCCESS", "compliance": compliance, "finding_data": scan_info}
            )

            prisma_scanner.deprovision_scanner(provisioned_product_name)
            ssm_client.delete_task_parameter(task_name)
    except ExitContainerScanner:
        logger.info("Exiting Container scanner!")
    except:
        logger.exception("Error while executing vulnerability scanner")