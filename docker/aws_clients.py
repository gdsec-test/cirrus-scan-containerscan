import json
from base64 import b64decode
import datetime
import boto3
import time
from botocore.exceptions import ClientError
from errors import SecretManagerRetrievalError, VPCNotFound,DeprovisioningScannerTimeoutError

# Deploy scanner instances using this ServiceCatalog offering version
SC_VERSION = "1.0.1"
ROLE_SESSION_NAME = "cirrus-scan"

class SecurityTokenServiceClient():
    """AWS STS Client to fetch AWS Credentials based on Role"""

    def __init__(self, logger):
        self.client = boto3.client("sts")
        self.logger = logger

    def get_account_id(self):
        return self.client.get_caller_identity().get("Account")

    def assume_role(self, role_arn):
        """Assume role and get AWS Credentials"""
        self.logger.info("Attempting to assume role: %s", role_arn)

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
            return credentials
        except ClientError:
            self.logger.exception("assume_role call failed for: %s", role_arn)
            raise SecretManagerRetrievalError


SECRET_NAME = "/CirrusScan/containerscan/prisma"
REGION_NAME = "us-west-2"

class SecretsManagerClient():
    """
    AWS Secrets Manager Client
    Used for interacting with AWS Secrets Manager service.
    """

    def __init__(self, logger):
        self.logger = logger

    def get_prisma_secrets(self, aws_creds):
        """Get prisma secrets (accesskeys) from secrets manager"""
        secret = response = None
        try:

            client = boto3.client("secretsmanager", REGION_NAME, **aws_creds)
            response = client.get_secret_value(SecretId=SECRET_NAME)


        except ClientError:
            raise SecretManagerRetrievalError
        else:
            if "SecretString" in response:
                response_secret = response["SecretString"]
            else:
                response_secret = b64decode(response["SecretBinary"])

        secret = json.loads(response_secret)

        if not secret:
            self.logger.error("Unable to retrieve prisma secrets")
            raise SecretManagerRetrievalError

        self.logger.info(
            "Successfully fetched an Prisma Secrets from Secrets Manager.")
        return secret


class S3Client():
    def __init__(self, logger):
        self.logger = logger
        self.client = boto3.client('s3')

    def upload_file(self, data, bucket, key):
        try:
            self.client.upload_file(data, bucket, key)
        except ClientError:
            self.logger.exception(
                f"put_object failed for: bucket: {bucket} with key: {key}")


class ECRClient():
    def __init__(self, logger):
        self.logger = logger

    def has_repositories(self, region):
        """Parse through parameters, and get scan targets"""
        try:
            client = boto3.client("ecr", region_name=region)
            response = client.describe_repositories()
            repositories_uris = [repo["repositoryUri"]
                                 for repo in response["repositories"]]
            return len(repositories_uris) > 0
        except ClientError:
            self.logger.error(f"Error while calling describe ECR in {region}")


class SSMClient():
    def __init__(self, logger):
        self.client = boto3.client("ssm")
        self.logger = logger

    def get_vpc_id(self):
        paramName = "/AdminParams/VPC/ID"
        return self.get_ssm_parameter_by_name(paramName)

    def get_org_type(self):
        orgtypeparam = "/AdminParams/Team/OrgType"
        return self.get_ssm_parameter_by_name(orgtypeparam)

    def get_ssm_parameter_by_name(self,param):

        try:
            response = self.client.get_parameter(Name=param)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ParameterNotFound":
                self.logger.debug("%s : Not found", param)
                return None
            raise

        if not response["Parameter"]:
            return None

        self.logger.debug("%s : %s", param, response["Parameter"]["Value"])
        return response["Parameter"]["Value"]

    def create_task_parameter(self, task_name):
        """Create persistent lock marker in Parameter Store"""

        expiration_time = datetime.datetime.now() + datetime.timedelta(hours=1)

        try:
            self.client.put_parameter(
                Name=task_name,
                Description="Container Scan Active Task",
                Value=str(expiration_time),
                Type="String",
                Tier="Standard",
                Overwrite=True,
            )
            self.logger.debug("SSM task parameter created: %s", task_name)
        except ClientError:
            self.logger.error(f"Failed to put task paramter : {task_name}")
            raise

    def has_task_parameter(self, task_name):
        return self.get_ssm_parameter_by_name(task_name) is not None

    def delete_task_parameter(self, task_name):
        """Remove persistent lock marker in Parameter Store"""

        self.client.delete_parameter(Name=task_name)

        self.logger.debug("SSM task parameter deleted: %s", task_name)


class EC2Client():
    def __init__(self, logger):
        self.logger = logger
        self.client = boto3.client("ec2")

    def get_defendername(self, vpc_id):

        scanner_dnsname = None
        try:
            response= self.client.describe_instances(
            Filters=[
                {"Name": "tag:Name", "Values": ["ContainerECRScanner"]},
                {"Name": "instance-state-name", "Values": ["running"]},
                {"Name": "vpc-id", "Values": [vpc_id]},
            ])

            scanner_dnsname = response["Reservations"][0]["Instances"][0]["NetworkInterfaces"][
                0
            ]["PrivateDnsName"]
            self.logger.info("Scanner name : %s" % scanner_dnsname)
        except KeyError:
            self.logger.error("Scanner IP not found")
            scanner_dnsname = None

        return scanner_dnsname



    def get_subnet_id(self, vpc_id):
        subnet_id = None
        response = self.client.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])

        for subnet in response["Subnets"]:
            if subnet["AvailableIpAddressCount"] > 4:
                for tag in subnet["Tags"]:
                    if tag["Key"] == "Name":
                        if "private" in tag["Value"]:
                            subnet_id = subnet["SubnetId"]
                            break
            if subnet_id != None:
                break

        if subnet_id is None:
            self.logger.info("No private subnet in VPC %s. Exiting!", vpc_id)
            raise VPCNotFound

        self.logger.debug("VPC ID: %s", vpc_id)
        self.logger.debug("Subnet Id: %s", subnet_id)

        return subnet_id

class ServiceCatalog():
    def __init__(self, logger):
        self.logger = logger
        self.client = boto3.client('servicecatalog')

    def provisioned_product_exists(self, provisioned_product_name):

        try:
            self.client.describe_provisioned_product(Name=provisioned_product_name)
        except self.client.exceptions.ResourceNotFoundException:
            return False

        self.logger.debug("Provisioned Product exists: %s", provisioned_product_name)
        return True

    def deprovision_scanner(self, provisioned_product_name):
        """Deprovision a container scanner"""
        self.logger.info("Deprovisioning container scanner")

        # Terminate VulnScanner Service Catalog Product from AWS account
        try:
            self.client.terminate_provisioned_product(
                ProvisionedProductName=provisioned_product_name
            )

            self.logger.info("container SC product terminated!")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                self.logger.info("ContainerScanner do not exist! No need to deprovision!")
            else:
                self.logger.error("Error in deleting the ContainerScanner SC product from AWS account")
                self.logger.error(e.response["Error"]["Message"])

        #wait for deprovisioning to complete
        for _ in range(15):
            if not self.provisioned_product_exists(provisioned_product_name):
                self.logger.info("container SC product successfully removed!")
                return
            time.sleep(60)

        self.logger.error("Deprovisioning timed out")
        raise DeprovisioningScannerTimeoutError

    def provision_scanner(self, vpc_id, subnet_id, provisioned_product_name):
        """Provision a Prisma scanner, using Service Catalog product EC2"""
        self.logger.info("Provisioning container scanner")

        # GetProductId
        response = self.client.search_products(Filters={"FullTextSearch": ["ContainerScanner"]})
        product_id = response["ProductViewSummaries"][0]["ProductId"]

        # Get other product details
        response = self.client.describe_product(Id=product_id)


        for provision_artifact in response["ProvisioningArtifacts"]:
            if provision_artifact["Name"] == SC_VERSION:
                provisioning_artifact_id = provision_artifact["Id"]

        response = self.client.provision_product(
            ProductId=product_id,
            # PathName="Compute",
            ProvisionedProductName=provisioned_product_name,
            ProvisioningArtifactId=provisioning_artifact_id,
            Tags=[{"Key": "doNotShutDown", "Value": "true"}],
            ProvisioningParameters=[                                                                        
                    {"Key": "InstanceType", "Value": "t3.large"}                                        
                ],
        )

        provisioned_product_id = response["RecordDetail"]["ProvisionedProductId"]
        self.logger.info("Provisioned Product ID: %s", provisioned_product_id)

        # Wait for product to be provisioned
        for _ in range(15):
            response = self.describe_provisioned_product_by_id(provisioned_product_id)
            if response["ProvisionedProductDetail"]["Status"] == "AVAILABLE":
                self.logger.info("Container Scanner successfully provisioned")
                break
            time.sleep(1*60)
        else:
            self.logger.error("Provisioning timed out")
            self.logger.error(response)
        return provisioned_product_name


    def describe_provisioned_product_by_id(self, provisioned_product_id):
        return self.client.describe_provisioned_product(Id=provisioned_product_id)
