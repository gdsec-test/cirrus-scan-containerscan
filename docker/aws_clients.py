import json
from base64 import b64decode
import datetime
import boto3
from botocore.exceptions import ClientError
from .errors import SecretManagerRetrievalError, VPCNotFound

# Deploy scanner instances using this ServiceCatalog offering version
SC_EC2_VERSION = "1.0.11"
AMI_IMAGE_ID = "/GoldenAMI/gd-amzn2-eks-1-17/latest"
ROLE_SESSION_NAME = "cirrus-scan"


class SecurityTokenServiceClient():
    def __init__(self, logger):
        self.client = boto3.client("sts")
        self.logger = logger

    def get_account_id(self):
        return self.client.get_caller_identity().get("Account")

    def assume_role(self, role_arn):
        """Attempt to assume the specified role_arn"""

        self.logger.info("Attempting to assume role: %s", role_arn)

        credentials = None
        try:
            response = self.client.assume_role(
                RoleArn=role_arn, RoleSessionName=ROLE_SESSION_NAME
            )
            credentials = {
                "aws_access_key_id": response["Credentials"]["AccessKeyId"],
                "aws_secret_access_key": response["Credentials"]["SecretAccessKey"],
                "aws_session_token": response["Credentials"]["SessionToken"],
            }
            self.logger.info("assume_role call succeeeded for: %s", role_arn)

        except ClientError:
            self.logger.exception("assume_role call failed for: %s", role_arn)

        return credentials


SECRET_NAME = "PrismaAccessKeys"
REGION_NAME = "us-west-2"


class SecretsManagerClient():
    # -*- coding: utf-8 -*-
    """
    AWS Secrets Manager Client
    Used for interacting with AWS Secrets Manager service.
    """

    def __init__(self, logger, creds):
        self.client = boto3.client("secretsmanager", REGION_NAME, **creds)
        self.logger = logger

    @staticmethod
    def handle_get_token_error(response):
        if response["Error"]["Code"] == "DecryptionFailureException":
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            return SecretManagerRetrievalError
        elif response["Error"]["Code"] == "InternalServiceErrorException":
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            return SecretManagerRetrievalError
        elif response["Error"]["Code"] == "InvalidParameterException":
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            return SecretManagerRetrievalError
        elif response["Error"]["Code"] == "InvalidRequestException":
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            return SecretManagerRetrievalError
        elif response["Error"]["Code"] == "ResourceNotFoundException":
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            return SecretManagerRetrievalError
        else:
            # Undocumented.
            return SecretManagerRetrievalError

    @staticmethod
    def decrypt_secret(response):
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if "SecretString" in response:
            secret = response["SecretString"]
        else:
            decoded_binary_secret = b64decode(
                response["SecretBinary"])

        secret = json.loads(response["SecretString"])

        return json.load(secret)

    def get_prisma_token_secrets(self):
        try:
            # Retrieving Tenable API keys
            response = self.client.get_secret_value(
                SecretId=SECRET_NAME)
        except ClientError as e:
            raise self.handle_get_token_error(e.response)

        return self.decrypt_secret(response)


class EC2Client():
    def __init__(self, logger):
        self.client = boto3.client("ec2")
        self.logger = logger
        # TODO(lmcdade): may be preferred that service catalog class in this file
        self.sc_client = boto3.client("servicecatalog")

    def describe_instances(self, vpc_id):
        return self.client.describe_instances(
            Filters=[
                {"Name": "tag:Name", "Values": ["ContainerScanner"]},
                {"Name": "instance-state-name", "Values": ["running"]},
                {"Name": "vpc-id", "Values": [vpc_id]},
            ])

    def get_ec2_product_id(self):
        response = self.sc_client.search_products(
            Filters={"FullTextSearch": ["EC2"]}
        )
        product_id = response["ProductViewSummaries"][0]["ProductId"]

        return product_id

    def get_ec2_product_description(self, product_id):
        response = self.sc_client.describe_product(Id=product_id)

        provisioning_artifact_id = None
        for provision_artifact in response["ProvisioningArtifacts"]:
            if provision_artifact["Name"] == SC_EC2_VERSION:
                provisioning_artifact_id = provision_artifact["Id"]

        if provisioning_artifact_id == None:
            raise RuntimeError("Unable to find provision artifact id")

        return provisioning_artifact_id

    def get_subnet_id(self, vpc_id):
        subnet_id = None
        response = self.client.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])

        for subnet in response["Subnets"]:
            if subnet["AvailableIpAddressCount"] > 4:
                for tag in subnet["Tags"]:
                    if tag["Key"] == "Name":
                        if "public" in tag["Value"]:
                            subnet_id = subnet["SubnetId"]
                            break
            if subnet_id != None:
                break

        if subnet_id is None:
            self.logger.info("No public subnet in VPC %s. Exiting!", vpc_id)
            raise VPCNotFound

        self.logger.debug("VPC ID: %s", vpc_id)
        self.logger.debug("Subnet Id: %s", subnet_id)

        return subnet_id

    def provision_ec2(self, provisioned_product_name, product_id, provisioning_artifact_id, vpc_id, subnet_id, script):
        # Provision VulnScanner Service Catalog Product

        response = self.sc_client.provision_product(
            ProductId=product_id,
            ProvisionedProductName=provisioned_product_name,
            ProvisioningArtifactId=provisioning_artifact_id,
            Tags=[{"Key": "doNotShutDown", "Value": "true"}],
            ProvisioningParameters=[
                {"Key": "VPCSubnetId", "Value": subnet_id},
                {"Key": "VPCId", "Value": vpc_id},
                {"Key": "CustomUserData", "Value": script},
                # {"Key": "InstanceType", "Value": "t2.large"},
                # TODO(lmcdade): Where does 'linking_key' below originate. Is it necessary?
                # {"Key": "TenableAPIKey", "Value": linking_key},
                # {"Key": "CustomIAMRoleNameSuffix", "Value": ROLE_NAME_SUFFIX},
                {"Key": "AMIImageId", "Value": AMI_IMAGE_ID}
            ],
        )

        provisioned_product_id = response["RecordDetail"]["ProvisionedProductId"]
        self.logger.info("Provisioned Product ID: %s", provisioned_product_id)

        return provisioned_product_id

    def describe_provisioned_product(self, provisioned_product_id):
        return self.client.describe_provisioned_product(Id=provisioned_product_id)


class S3Client():
    def __init__(self, logger):
        self.logger = logger
        self.client = boto3.client('s3')

    def upload_file(self, data, bucket, key):
        try:
            s3_client = S3Client(self.logger)
            self.client.upload_file(data, bucket, key)
        except ClientError:
            self.logger.exception(
                "put_object failed for: bucket: %s with key: %s",
                bucket,
                key,
            )


class ServiceCatalog():
    def __init__(self, logger):
        self.logger = logger
        self.client = boto3.client('servicecatalog')

    def terminate_provisioned_product(self, provisioned_product_name):
        # Terminate VulnScanner Service Catalog Product from AWS account
        try:
            sc_client = ServiceCatalog(self.logger)
            response = self.client.terminate_provisioned_product(
                ProvisionedProductName=provisioned_product_name
            )

            self.logger.info("VulnScanner SC product successfully deleted!")

        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                self.logger.info(
                    "VulnScanner do not exist! No need to deprovision!")
            else:
                self.logger.error(
                    "Error in deleting the VulnScanner SC product from AWS account")
                self.logger.error(e.response["Error"]["Message"])


class ECRClient():
    def __init__(self, region):
        self.client = boto3.client("ecr", region_name=region)

    def does_repository_have_repos(self):
        """Parse through parameters, and get scan targets"""

        repositories = self.client.describe_repositories()["repositories"]
        repositories_uris = [repository["repositoryUri"]
                             for repository in repositories]

        return len(repositories_uris) > 0


class SSMClient():
    def __init__(self, logger):
        self.client = boto3.client("ss")
        self.logger = logger

    def create_task_parameter(self, task_name):
        """Create persistent lock marker in Parameter Store"""

        expiration_time = datetime.datetime.now() + datetime.timedelta(hours=1)

        self.client.put_parameter(
            Name=task_name,
            Description="Container Scan Active Task",
            Value=str(expiration_time),
            Type="String",
            Tier="Standard",
            Overwrite=True,
        )

        self.logger.debug("SSM task parameter created: %s", task_name)

    def get_task_parameter(self, task_name):
        """Obtain task parameter from Parameter Store"""

        try:
            response = self.client.get_parameter(Name=task_name)

        except ClientError as e:
            if e.response["Error"]["Code"] == "ParameterNotFound":
                self.logger.debug("%s : Not found", task_name)
                return None
            raise

        if not response["Parameter"]:
            return None

        self.logger.debug("%s : %s", task_name, response["Parameter"]["Value"])
        return response["Parameter"]["Value"]

    def delete_task_parameter(self, task_name):
        """Remove persistent lock marker in Parameter Store"""

        self.client.delete_parameter(Name=task_name)

        self.logger.debug("SSM task parameter deleted: %s", task_name)
