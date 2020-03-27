#!/usr/bin/python3

"""\
CirrusScan wrapper for container-based checks.

This script wraps calls to AWS services so that checks do not have to read
parameters from AWS or worry about copying output files to S3 buckets.

The following environment variables are consulted when this script is invoked:

# https://boto3.readthedocs.io/en/latest/guide/configuration.html#configuring-credentials

    AWS_ACCESS_KEY_ID: The access key for your AWS account.
    AWS_SECRET_ACCESS_KEY: The secret key for your AWS account.
    AWS_SESSION_TOKEN: The session key for your AWS account.

When running in the context of a container, AWS credentials are provided via:

# https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html

    AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

Input to this container is provided via a JSON data structure that is contained
in a specified (bucket,object) data pair:

    BUCKET_ID: Bucket ID containing input parameters.
    OBJECT_ID: Key of object within BUCKET_ID containing input parameters.

The JSON retrieved from the bucket specified above is expected to contain the
following parameters:

    commands (required)
        array of commands to be executed to perform the check

    environment (optional)
        specifies any optional environment variables that should be defined

    inputs (optional)
        specifies any input files that should be copied from S3 buckets

    outputs (optional)
        specifies any output files that should be copied to S3 buckets

    status_bucket (optional)
    status_object (optional)
        specifies the S3 bucket and object that should be updated with the task
        status upon completion

    parameters (optional)
        specifies additional data that may be useful to the task. If this is
        present and contains the key "arg", the value of that key will be
        written to the file "CIRRUSSCAN_ARG" before commands are executed.
        (If "arg" is not present, the file will not be created.) This dictionary
        can be retrieved by calling wrapper.get_parameters().

Example:

{
    "commands": [
        "run_check.sh"
    ],
    "environment": [
        {
            "name": "VERBOSE",
            "value": "1"
        }
    ],
    "parameters": {
        "arg": "1.2.3.0/24",
        "severity": 50
    },
    "inputs": [],
    "outputs": [
        {
            "bucket": "cirrus-scan-example-output",
            "object": "template/output.txt",
            "file": "output.txt"
        }
    ]
}

"""

import json
import logging
import os
import subprocess
import sys
import time

import boto3

log = logging.getLogger(__name__)
log.setLevel(level=logging.DEBUG)

logging_handler = logging.StreamHandler()
logging_formatter = logging.Formatter("[%(levelname)s] %(asctime)s %(message)s")
logging_handler.setFormatter(logging_formatter)
log.addHandler(logging_handler)

STATUS_FILE = "CIRRUSSCAN_STATUS"
ARGUMENT_FILE = "CIRRUSSCAN_ARG"
PARAMETER_FILE = "CIRRUSSCAN_PARAMETERS"

variable_parameters = None


def put_status(status_dict):
    """Save supplied status (dictionary) into an exchange file"""

    try:
        with open(STATUS_FILE, "w") as f:
            json.dump(status_dict, f)
        log.debug("Transferred status data to %s", STATUS_FILE)
    except:
        log.error("Unable to save status data to %s", STATUS_FILE)


def get_status():
    """Retrieve status (dictionary) from an exchange file"""

    try:
        with open(STATUS_FILE, "r") as f:
            status_dict = json.load(f)
        log.debug("Transferred status data from %s", STATUS_FILE)
        return status_dict
    except:
        log.error("Unable to retrieve status data from %s", STATUS_FILE)
        return {}


def get_parameters(default={}):
    """Retrieve variable parameters (dictionary) from task request"""

    global variable_parameters

    # Transparently reload from state file if we haven't done so yet
    if variable_parameters is None:
        try:
            with open(PARAMETER_FILE, "r") as f:
                variable_parameters = json.load(f)
        except:
            log.error("No file %s to re-read", PARAMETER_FILE)

    if variable_parameters is None:
        return default
    return variable_parameters


def resolve_parameter(raw_value, default_value=None):
    """Retrieve remote parameter values"""

    # If the input parameter does NOT begin with "s3://", return it
    # unchanged. Otherwise, we assume this is a S3 reference and
    # retrieve the specified object, returning it (unmodified). If
    # we encounter a problem retrieving the object, return the
    # default value.

    try:
        if raw_value.startswith("s3://"):
            # S3 reference, s3://bucket/key
            _, _, s3_bucket, s3_key = raw_value.split("/", 3)
            log.debug("Retrieving S3 content from %s / %s", s3_bucket, s3_key)
            s3 = boto3.client("s3")
            info = s3.get_object(Bucket=s3_bucket, Key=s3_key)
            streamer = info["Body"]
            return streamer.read().decode("utf-8")

        # Default... Unrecognized must be literal data
        return raw_value

    except Exception as e:
        log.exception("Exception retrieving content:")
        return default_value


def main():

    s3 = boto3.client("s3")

    if "BUCKET_ID" not in os.environ:
        sys.exit("BUCKET_ID is not set")
    elif "OBJECT_ID" not in os.environ:
        sys.exit("OBJECT_ID is not set")
    elif not os.environ["BUCKET_ID"]:
        sys.exit("BUCKET_ID is empty")
    elif not os.environ["OBJECT_ID"]:
        sys.exit("OBJECT_ID is empty")

    bucket_id = os.environ["BUCKET_ID"]
    object_id = os.environ["OBJECT_ID"]

    log.info("BUCKET_ID: %s", bucket_id)
    log.info("OBJECT_ID: %s", object_id)

    # Attempt to parse the parameters contained in the specified bucket

    try:
        params_str = (
            s3.get_object(Bucket=bucket_id, Key=object_id)["Body"]
            .read()
            .decode("UTF-8")
        )
        log.debug("Parameters (original):\n%s", params_str)
        params_dict = json.loads(params_str)
        log.debug("Parameters (parsed): %s", json.dumps(params_dict))
    except Exception as e:
        log.exception("Unable to parse parameter JSON")

    # Set environment variables

    try:
        if "environment" in params_dict:
            for env_entry in params_dict["environment"]:
                if "name" in env_entry and "value" in env_entry:
                    log.debug(
                        "Setting environment variable [%s] = [%s]",
                        env_entry["name"],
                        env_entry["value"],
                    )
                    os.environ[env_entry["name"]] = env_entry["value"]
    except Exception as e:
        log.exception("Unable to set environment variables")

    # Save variable parameters. We need to put them into a file also,
    # so we can read them back later if we get a callback (in a new
    # process) to access it. Automatically attempt to resolve the arg
    # parameter before writing so we can execute clueless external
    # programs transparently.

    global variable_parameters
    try:
        if "parameters" in params_dict:
            variable_parameters = params_dict["parameters"]
            if "arg" in variable_parameters:
                log.debug(
                    "Creating %s with '%s'", ARGUMENT_FILE, variable_parameters["arg"]
                )
                explode = resolve_parameter(variable_parameters["arg"], "")
                variable_parameters["arg"] = explode
                with open(ARGUMENT_FILE, "w") as f:
                    f.write(explode)
            with open(PARAMETER_FILE, "w") as f:
                json.dump(variable_parameters, f)
    except Exception as e:
        log.exception("Unable to process variable parameters")

    # Copy input files

    try:
        if "inputs" in params_dict:
            for file_entry in params_dict["inputs"]:
                if (
                    "bucket" in file_entry
                    and "object" in file_entry
                    and "file" in file_entry
                ):
                    log.debug(
                        "Copying input file [%s] from s3://%s/%s",
                        file_entry["file"],
                        file_entry["bucket"],
                        file_entry["object"],
                    )
                    s3.download_file(
                        Bucket=file_entry["bucket"],
                        Key=file_entry["object"],
                        Filename=file_entry["file"],
                    )
    except Exception as e:
        log.exception("Unable to copy input files")

    # Execute commands

    try:
        if "commands" in params_dict:
            for command in params_dict["commands"]:
                log.info("Executing command: %s", command)
                return_code = subprocess.call(command, shell=True)
                log.debug("Return code: %d", return_code)
        else:
            log.error("No commands specified in parameter JSON")
    except Exception as e:
        log.exception("Unable to execute commands")

    # Copy output files

    try:
        if "outputs" in params_dict:
            for file_entry in params_dict["outputs"]:
                if (
                    "bucket" in file_entry
                    and "object" in file_entry
                    and "file" in file_entry
                ):
                    log.debug(
                        "Copying output file [%s] to s3://%s/%s",
                        file_entry["file"],
                        file_entry["bucket"],
                        file_entry["object"],
                    )
                    s3.upload_file(
                        Filename=file_entry["file"],
                        Bucket=file_entry["bucket"],
                        Key=file_entry["object"],
                        ExtraArgs={"ACL": "bucket-owner-full-control"},
                    )
    except Exception as e:
        log.exception("Unable to copy output files")

    # Update task status

    try:
        if "status_bucket" in params_dict and "status_object" in params_dict:
            status_entry = get_status()
            if "timestamp" not in status_entry:
                status_entry["timestamp"] = time.time()
            if "status" not in status_entry:
                status_entry["status"] = "COMPLETE"
            log.debug(
                "Updating task status in s3://%s/%s",
                params_dict["status_bucket"],
                params_dict["status_object"],
            )
            status_json = json.dumps(status_entry)
            log.debug("status: %s", status_json)
            s3.put_object(
                Body=status_json,
                Bucket=params_dict["status_bucket"],
                Key=params_dict["status_object"],
                ACL="bucket-owner-full-control",
            )
    except Exception as e:
        log.exception("Unable to update task status")


if __name__ == "__main__":
    main()
