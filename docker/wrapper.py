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
in a specified (bucket,key) data pair:

    BUCKET_ID: Bucket containing input parameters.
    BUCKET_KEY: Key within BUCKET_ID containing input parameters.

The JSON retrieved from the bucket specified above is expected to contain the
following parameters:

    commands (required)
        array of commands to be executed to perform the check

    environment (optional)
        specifies any optional environment variables that should be defined

    inputs (optional)
        specifies any input files that should be copied from S3 buckets

    outputs (optional)
        specifies any ouput files that should be copied to S3 buckets

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
    "inputs": [],
    "outputs": [
        {
            "bucket_id": "cirrus-scan-example-output",
            "bucket_key": "template/output.txt",
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

import boto3

s3 = boto3.client('s3')

if 'BUCKET_ID' not in os.environ:
    sys.exit('BUCKET_ID is not set')
elif 'BUCKET_KEY' not in os.environ:
    sys.exit('BUCKET_KEY is not set')
elif not os.environ['BUCKET_ID']:
    sys.exit('BUCKET_ID is empty')
elif not os.environ['BUCKET_KEY']:
    sys.exit('BUCKET_KEY is empty')

log = logging.getLogger()
log.setLevel(level=logging.DEBUG)

bucket_id = os.environ['BUCKET_ID']
bucket_key = os.environ['BUCKET_KEY']

log.info('BUCKET_ID: %s', bucket_id)
log.info('BUCKET_KEY: %s', bucket_key)

# Attempt to parse the parameters contained in the specified bucket

try:
    params_str = s3.get_object(Bucket=bucket_id, Key=bucket_key)['Body'].read().decode('UTF-8')
    log.debug('Parameters (str): %s', params_str)
    params_dict = json.loads(params_str)
    log.debug('Parameters (dict): %s', params_dict)
except Exception as e:
    log.exception('Unable to parse parameter JSON')

# Set environment variables

try:
    if 'environment' in params_dict:
        for env_entry in params_dict['environment']:
            if 'name' in env_entry and 'value' in env_entry:
                log.debug('Setting environment variable [%s] = [%s]', env_entry['name'], env_entry['value'])
                os.environ[env_entry['name']] = env_entry['value']
except Exception as e:
    log.exception('Unable to set environment variables')

# Copy input files

try:
    if 'inputs' in params_dict:
        for file_entry in params_dict['inputs']:
            if 'bucket_id' in file_entry and 'bucket_key' in file_entry and 'file' in file_entry:
                log.debug('Copying input file [%s] from s3://%s/%s', file_entry['file'], file_entry['bucket_id'], file_entry['bucket_key'])
                s3.download_file(Bucket=file_entry['bucket_id'], Key=file_entry['bucket_key'], Filename=file_entry['file'])
except Exception as e:
    log.exception('Unable to copy input files')

# Execute commands

try:
    if 'commands' in params_dict:
        for command in params_dict['commands']:
            log.info('Executing command: %s', command)
            return_code = subprocess.call(command, shell=True)
            log.debug('Return code: %d', return_code)
    else:
        log.error('No commands specified in parameter JSON')
except Exception as e:
    log.exception('Unable to execute commands')

# Copy output files

try:
    if 'outputs' in params_dict:
        for file_entry in params_dict['outputs']:
            if 'bucket_id' in file_entry and 'bucket_key' in file_entry and 'file' in file_entry:
                log.debug('Copying output file [%s] to s3://%s/%s', file_entry['file'], file_entry['bucket_id'], file_entry['bucket_key'])
                s3.upload_file(Filename=file_entry['file'], Bucket=file_entry['bucket_id'], Key=file_entry['bucket_key'])
except Exception as e:
    log.exception('Unable to copy output files')
