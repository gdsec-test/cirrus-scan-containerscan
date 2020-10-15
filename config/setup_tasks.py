#!/usr/bin/env python

import json
import boto3


def main():
    sts = boto3.client("sts")
    audit_account_id = sts.get_caller_identity()["Account"]

    # ECR that holds this container
    task_image = "%s.dkr.ecr.us-west-2.amazonaws.com/prismascan" % audit_account_id

    # Configuration parameters used by wrapper.py
    dynamodb = boto3.resource("dynamodb")

    task_parameters = json.loads(open("task_parameters.json").read())
   
    # Default task configuration
    task_config = {
        "TASK_NAME": "prismascan",
        "TASK_SCOPE": "REGION",
        "TASK_CPU": "1024",
        "TASK_MEMORY": "2048",
        "TASK_IMAGE": task_image,
        "TASK_PARAMETERS": task_parameters,
        "TASK_SCHEDULE": "scheduler-daily-rule",  
    }
   
    
    task = dynamodb.Table("task")

    task.put_item(
        Item={"key": "prismascan", "value": task_config}
    )


if __name__ == "__main__":
    main()
