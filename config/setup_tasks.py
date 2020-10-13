#!/usr/bin/env python

import json
import boto3


def main():
    sts = boto3.client("sts")
    audit_account_id = sts.get_caller_identity()["Account"]

    # Limit execution to the following list of accounts
    aws_accounts = [
        "FIXME1",  # TBD Dev-Private
        "FIXME2",  # TBD Prod
    ]

    # ECR that holds this container
    task_image = "%s.dkr.ecr.us-west-2.amazonaws.com/portscan" % audit_account_id

    # Configuration parameters used by wrapper.py
    task_configuration = json.loads(open("task_configuration.json").read())

    # Parameter table data, indexed by account
    task_parameters = json.loads(open("task_parameters.json").read())

    dynamodb = boto3.resource("dynamodb")

    # Write parameter data first to avoid race conditions
    parameter = dynamodb.Table("parameter")

    # Write default settings, by account, to the parameter table
    for account in task_parameters:
        parameter.put_item(
            Item={
                "task": "portscan",
                "account": account,
                "value": task_parameters[account],
            }
        )

    # Write task data
    task = dynamodb.Table("task")

    task.put_item(
        Item={
            "key": "portscan",
            "value": {
                "AWS_ACCOUNTS": aws_accounts,
                "TASK_NAME": "portscan",
                "TASK_CPU": "512",
                "TASK_MEMORY": "1024",
                "TASK_IMAGE": task_image,
                "TASK_PARAMETERS": task_configuration,
                "TASK_SCHEDULE": "manual",
            },
        }
    )


if __name__ == "__main__":
    main()
