#!/usr/bin/env python3

import datetime
import json
import logging
import os
import boto3

import common.securityhub
import wrapper

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


def generate_informational_finding(handle, scope_name):
    """Generate an informational finding indicating scan is complete"""

    log.debug("Scan complete")

    # Generate a Security Hub finding
    f = handle.Finding("portscan/complete/" + scope_name)

    f.ProductFields["Environment"] = os.getenv(
        "CIRRUS_SCAN_ACCOUNT_ENVIRONMENT", "UNKNOWN"
    )
    f.ProductFields["TaskUuid"] = os.getenv("CIRRUS_SCAN_TASK_UUID", "UNKNOWN")
    f.ProductFields["TeamName"] = os.getenv("CIRRUS_SCAN_ACCOUNT_TEAM_NAME", "UNKNOWN")

    f.Title = "%s portscan: finished scan at %s" % (
        scope_name,
        datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    f.Compliance = {"Status": "PASSED"}
    f.Description = "No description available."
    f.GeneratorId = "portscan"

    f.save()


if __name__ == "__main__":
    # Adjust log format and content
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s"
    )

    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.INFO)
    logging.getLogger("urllib3").setLevel(logging.CRITICAL)

    # Get parameters from caller
    parameters = wrapper.get_parameters()
    exception_rules = wrapper.get_exception_rules()

    scope_name = parameters.get("scope", "default")

    # Initialize Security Hub context
    handle = common.securityhub.SecurityHub_Manager(exception_rules=exception_rules)
    handle.begin_transaction(scope_prefix="portscan/" + scope_name + "/")

    # +----------------------------+
    # |  ALL SCAN LOGIC GOES HERE  |
    # +----------------------------+

    # Report scan completion and flush changes to Security Hub
    generate_informational_finding(handle, scope_name)
    handle.end_transaction(autoarchive=True)

    # Grab some information about what we found and forward it back
    # to wrapper so it can be reported. We are compliant if no findings
    # exist with severities greater than 69. (aka LOW and MEDIUM are
    # permissible, but not HIGH or CRITICAL -- and high starts at 70.)
    scan_info = handle.get_finding_data()
    compliance = "PASS"
    for severity in scan_info["severity"]:
        if severity >= 70:
            compliance = "FAIL"
            break
    wrapper.put_status(
        {"status": "SUCCESS", "compliance": compliance, "finding_data": scan_info}
    )
