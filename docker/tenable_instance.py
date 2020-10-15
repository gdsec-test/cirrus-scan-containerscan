#!/usr/bin/env python3

import datetime
import logging
import time

import boto3

from botocore.exceptions import ClientError

log = logging.getLogger(__name__)  # pylint: disable=invalid-name


class TenableInstance:
    def __init__(self, vpc_id, provision_hook, deprovision_hook):
        self.task_name = "vulnscan"
        self.vpc_id = vpc_id
        self.provision_hook = provision_hook
        self.deprovision_hook = deprovision_hook
        self.polling_interval = 20
        self.timeout = datetime.timedelta(hours=3)  # How long can a lock persist?
        self.ssm = boto3.client("ssm")
        # Scanner name must match service catalog definition
        self.scanner_name = "VulnScanner-" + self.vpc_id

        # This should end with "/" to simplify logic below
        self.task_state_path = (
            "/CirrusScan/" + self.task_name + "/" + vpc_id + "/users/"
        )

        # This parameter name *MUST* match the parameter provisioned by
        # the Service Catalog product to operate correctly.
        self.state_parameter = "/CirrusScan/" + self.task_name + "/" + vpc_id + "/state"

    # These are the low-level state transition functions. Each is called with no
    # arguments and should return the (new) current state.

    def do_provision_hook(self):
        """Transition from DEPROVISIONED to PROVISIONING"""

        # Call the user-specified provisioning hook. We expect this hook will
        # (eventually) set the state to PROVISIONING when Service Catalog has
        # finished deploying the scanner.
        try:
            self.provision_hook(self.vpc_id)
            return self.get_ssm_state_parameter()
        except ClientError as oops:
            if oops.response["Error"]["Code"] not in (
                "DuplicateResourceException",
                "InvalidParametersException",
            ):
                log.error("Provisioning failure: %s", oops)
                return "ERROR"
            # The resource already exists; fall through
        except Exception as oops:
            log.error("Provisioning failure: %s", oops)
            return "ERROR"

        # Here on DuplicateResourceException|InvalidParametersException
        # The resource already exists due to another request; wait for
        # Service Catalog to finish deployment
        log.debug("Waiting for provisioning already in progress...")
        for setup_count in range(20):
            time.sleep(self.polling_interval)
            current_state = self.get_ssm_state_parameter()
            if current_state is not None:
                return current_state
        log.error("Provisioning failure: timeout waiting for provisioning")
        return "ERROR"

    def make_operational(self):
        """Transition from PROVISIONING to OPERATIONAL"""

        # This is basically a no-op. We expect the caller will check with Tenable
        # to determine the scanner is actually ready to do work.
        return self.update_ssm_state_parameter("OPERATIONAL")

    def do_deprovision_hook(self):
        """Transition from OPERATIONAL to DEPROVISIONING"""

        # Call the user-specified deprovisioning hook, after indicating we are
        # going to tear down the scanner instance.
        current_state = self.update_ssm_state_parameter("DEPROVISIONING")
        try:
            self.deprovision_hook(self.scanner_name)
            return current_state
        except ClientError as oops:
            if oops.response["Error"]["Code"] == "ResourceNotFoundException":
                # Somebody deleted it before us, don't worry about it
                return current_state
            log.error("Deprovisioning failure: %s", oops)
            return "ERROR"
        except Exception as oops:
            log.error("Deprovisioning failure: %s", oops)
            return "ERROR"

    def wait_for_deprovisioning(self):
        """Transition from DEPROVISIONING to DEPROVISIONED (None)"""

        # Wait for Service Catalog to finish tearing down the scanner. We
        # expect this will include removal of the state parameter itself.
        log.debug("Waiting for deprovisioning...")
        for setup_count in range(20):
            time.sleep(self.polling_interval)
            current_state = self.get_ssm_state_parameter()
            if current_state != "DEPROVISIONING":
                return current_state
        log.error("Deprovisioning failure: timeout waiting for deprovisioning")
        return "ERROR"

    # This dict expresses the transition table for the locking finite state machine.
    # Note that we depart from traditional practice by not specifying the input
    # symbol for each transition, on the theory that either only a single valid
    # transition exists, or that the implementation function is able to handle
    # any ambiguity. None represents the "DEPROVISIONED" state. The special state
    # "ERROR" does not appear in the table.

    # <current-state>: <transition-function-for-next-state>
    state_table = {
        None: do_provision_hook,
        "PROVISIONING": make_operational,
        "OPERATIONAL": do_deprovision_hook,
        "DEPROVISIONING": wait_for_deprovisioning,
    }

    # This is the high-level state machine which executes the state table

    def state_change(self, new_state):
        """Execute state machine until reaching desired state"""

        # Execute transitions until we reach the desired state or the ERROR state
        current_state = self.get_ssm_state_parameter()
        log.debug("Start state is %s", current_state)

        while True:
            if current_state == new_state:
                # Success!
                log.debug("Reached desired state - SUCCESS")
                return True

            # Move to the next state
            current_state = (
                self.state_table[current_state](self)
                if current_state in self.state_table
                else "ERROR"
            )
            log.debug("Moved to state %s", current_state)

            if current_state == "ERROR":
                # Something broke
                raise RuntimeError("Reached ERROR instead of %s - FAILURE" % new_state)

    # Low-level routines for maintaining the current state in Parameter Store,
    # where it is visible to all cooperating processes.

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
