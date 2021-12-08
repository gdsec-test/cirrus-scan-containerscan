import datetime
import unittest
from base64 import b64decode, b64encode
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError
import sys
import json

# Add the docker subdirectory to the module search path
sys.path.append("docker")

# pylint: disable=import-error no-name-in-module
import aws_clients
from errors import (
    SecretManagerRetrievalError,
    VPCNotFound,
    DeprovisioningScannerTimeoutError,
)

# pylint: enable=import-error no-name-in-module

FAKE_CLIENT_ERROR = ClientError(
    {"Error": {"Code": "some", "Message": "Unit Test"}},
    "fake client error?",
)


class SecurityTokenServiceClientTest(unittest.TestCase):
    FAKE_ACCOUNT = {"Account": "FakeAccountId"}
    FAKE_CREDENTIALS = {
        "aws_access_key_id": "test",
        "aws_secret_access_key": "test2",
        "aws_session_token": "test3",
    }

    def _mock_assume_role(self, RoleArn=None, RoleSessionName=None):
        if RoleArn is not None and RoleSessionName == aws_clients.ROLE_SESSION_NAME:
            return {
                "Credentials": {
                    "AccessKeyId": self.FAKE_CREDENTIALS["aws_access_key_id"],
                    "SecretAccessKey": self.FAKE_CREDENTIALS["aws_secret_access_key"],
                    "SessionToken": self.FAKE_CREDENTIALS["aws_session_token"],
                }
            }

        raise Exception(f"Assume role called with unexpected {RoleSessionName}")

    @patch("aws_clients.boto3.client")
    def setUp(self, mock_boto):
        self.logger = MagicMock()
        self.mock_sts = MagicMock()

        self.mock_sts.get_caller_identity.return_value = self.FAKE_ACCOUNT
        self.mock_sts.assume_role.side_effect = self._mock_assume_role

        mock_boto.return_value = self.mock_sts

        self.subject = aws_clients.SecurityTokenServiceClient(self.logger)

    def test_get_account_id_should_return_account_id(self):
        self.assertEqual(self.subject.get_account_id(), self.FAKE_ACCOUNT["Account"])

    def test_assume_role_should_return_credentials(self):
        self.assertEqual(
            self.subject.assume_role("some_role_arn"), self.FAKE_CREDENTIALS
        )

    def test_assume_role_should_throw_SecretManagerRetrievalError(self):
        self.mock_sts.assume_role.side_effect = FAKE_CLIENT_ERROR
        with self.assertRaises(SecretManagerRetrievalError):
            self.subject.assume_role("some_role_arn")


@patch("aws_clients.boto3.client")
class SecretsManagerClientTest(unittest.TestCase):
    FAKE_SECRET = {"key": "VERY SECRET"}
    FAKE_CREDENTIALS = {
        "aws_access_key_id": "test",
        "aws_secret_access_key": "test2",
        "aws_session_token": "test3",
    }

    def _mock_get_secret_value_of(self, encoded=False):
        def _mock_get_secret_value(SecretId):
            if SecretId == aws_clients.SECRET_NAME and encoded is False:
                return {"SecretString": json.dumps(self.FAKE_SECRET)}
            elif SecretId == aws_clients.SECRET_NAME and encoded is True:
                return {
                    "SecretBinary": b64encode(
                        json.dumps(self.FAKE_SECRET).encode("ascii")
                    )
                }

            raise Exception(f"get_secret_value called with unexpected {SecretId}")

        return _mock_get_secret_value

    def setUp(self):
        self.logger = MagicMock()
        self.mock_asm = MagicMock()

        self.mock_asm.get_secret_value.side_effect = self._mock_get_secret_value_of()

        self.subject = aws_clients.SecretsManagerClient(self.logger)

    def test_get_prisma_secrets_should_return_secret(self, mock_boto):
        mock_boto.return_value = self.mock_asm
        self.assertEqual(
            self.subject.get_prisma_secrets(self.FAKE_CREDENTIALS),
            self.FAKE_SECRET,
        )

    def test_get_prisma_secrets_should_return_encoded_secret(self, mock_boto):
        self.mock_asm.get_secret_value.side_effect = self._mock_get_secret_value_of(
            True
        )
        mock_boto.return_value = self.mock_asm
        self.assertEqual(
            self.subject.get_prisma_secrets(self.FAKE_CREDENTIALS),
            self.FAKE_SECRET,
        )

    def test_get_prisma_secrets_raise_SecretManagerRetrievalError_when_boto_error(
        self, mock_boto
    ):
        self.mock_asm.get_secret_value.side_effect = FAKE_CLIENT_ERROR
        mock_boto.return_value = self.mock_asm
        with self.assertRaises(SecretManagerRetrievalError):
            self.subject.get_prisma_secrets(self.FAKE_CREDENTIALS)

    def test_get_prisma_secrets_raise_SecretManagerRetrievalError_when_no_secret_found(
        self, mock_boto
    ):
        self.mock_asm.get_secret_value.side_effect = lambda SecretId: {
            "SecretString": json.dumps("")
        }
        mock_boto.return_value = self.mock_asm
        with self.assertRaises(SecretManagerRetrievalError):
            self.subject.get_prisma_secrets(self.FAKE_CREDENTIALS)


@patch("aws_clients.boto3.client")
class S3ClientTest(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()
        self.mock_s3 = MagicMock()

        self.mock_s3.upload_file.return_value = None

    def test_upload_file_should_works(self, mock_boto):
        mock_boto.return_value = self.mock_s3
        subject = aws_clients.S3Client(self.logger)
        self.assertEqual(
            subject.upload_file("test-data", "test-bucket", "test-key"), None
        )

    def test_upload_file_should_not_throw(self, mock_boto):
        self.mock_s3.upload_file.side_effect = FAKE_CLIENT_ERROR
        mock_boto.return_value = self.mock_s3
        subject = aws_clients.S3Client(self.logger)
        self.assertEqual(
            subject.upload_file("test-data", "test-bucket", "test-key"), None
        )


@patch("aws_clients.boto3.client")
class ECRClientTest(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()
        self.mock_ecr = MagicMock()

        self.mock_ecr.describe_repositories.return_value = {
            "repositories": [{"repositoryUri": "something"}]
        }

        self.subject = aws_clients.ECRClient(self.logger)

    def test_has_repositories_should_return_true_when_length_not_zero(self, mock_boto):
        mock_boto.return_value = self.mock_ecr
        self.assertTrue(self.subject.has_repositories("region"))

    def test_has_repositories_should_return_false_when_length_zero(self, mock_boto):
        self.mock_ecr.describe_repositories.return_value = {"repositories": []}
        mock_boto.return_value = self.mock_ecr
        self.assertFalse(self.subject.has_repositories("region"))

    def test_has_repositories_should_not_throw(self, mock_boto):
        self.mock_ecr.describe_repositories.side_effect = FAKE_CLIENT_ERROR
        mock_boto.return_value = self.mock_ecr
        self.assertEqual(self.subject.has_repositories("region"), None)


@patch("aws_clients.boto3.client")
class SSMClientTest(unittest.TestCase):
    VPC_ID_PARAM = "/AdminParams/VPC/ID"
    ORG_TYPE_PARAM = "/AdminParams/Team/OrgType"

    VPC_ID_VALUE = "test-vpc"
    ORG_TYPE_VALUE = "best-team"

    def _mock_get_parameter(self, Name):
        v = {}
        if Name == self.VPC_ID_PARAM:
            v = {"Value": self.VPC_ID_VALUE}
        elif Name == self.ORG_TYPE_PARAM:
            v = {"Value": self.ORG_TYPE_VALUE}

        return {"Parameter": v}

    def setUp(self):
        self.logger = MagicMock()
        self.mock_ssm = MagicMock()

        self.mock_ssm.get_parameter.side_effect = self._mock_get_parameter
        self.mock_ssm.put_parameter = MagicMock()
        self.mock_ssm.delete_parameter = MagicMock()

    def test_get_vpc_id_returns_vpc_id_value(self, mock_boto):
        mock_boto.return_value = self.mock_ssm
        subject = aws_clients.SSMClient(self.logger)

        self.assertEqual(subject.get_vpc_id(), self.VPC_ID_VALUE)

    def test_get_org_type_returns_org_type_value(self, mock_boto):
        mock_boto.return_value = self.mock_ssm
        subject = aws_clients.SSMClient(self.logger)

        self.assertEqual(subject.get_org_type(), self.ORG_TYPE_VALUE)

    def test_get_ssm_parameter_by_name_returns_None_when_no_parameter_value(
        self, mock_boto
    ):
        mock_boto.return_value = self.mock_ssm
        subject = aws_clients.SSMClient(self.logger)

        self.assertIsNone(subject.get_ssm_parameter_by_name(""))

    def test_get_ssm_parameter_by_name_returns_None_when_ClientError_with_ParameterNotFound(
        self, mock_boto
    ):
        self.mock_ssm.get_parameter.side_effect = ClientError(
            {"Error": {"Code": "ParameterNotFound", "Message": "Unit Test"}},
            "fake client error?",
        )
        mock_boto.return_value = self.mock_ssm
        subject = aws_clients.SSMClient(self.logger)

        self.assertIsNone(subject.get_ssm_parameter_by_name(""))

    def test_get_ssm_parameter_by_name_raises_when_ClientError_with_unkown_code(
        self, mock_boto
    ):
        self.mock_ssm.get_parameter.side_effect = FAKE_CLIENT_ERROR
        mock_boto.return_value = self.mock_ssm
        subject = aws_clients.SSMClient(self.logger)
        with self.assertRaises(ClientError):
            subject.get_ssm_parameter_by_name("")

    def test_create_task_parameter_calls_put_parameter_with_ssm(self, mock_boto):
        mock_boto.return_value = self.mock_ssm
        subject = aws_clients.SSMClient(self.logger)

        subject.create_task_parameter("task name")
        self.mock_ssm.put_parameter.assert_called_once()

    def test_create_task_parameter_raises_ClientError_with_boto_error(self, mock_boto):
        self.mock_ssm.put_parameter.side_effect = FAKE_CLIENT_ERROR
        mock_boto.return_value = self.mock_ssm
        subject = aws_clients.SSMClient(self.logger)

        with self.assertRaises(ClientError):
            subject.create_task_parameter("task name")

    def test_has_task_parameter_returns_True_when_parater_found(self, mock_boto):
        mock_boto.return_value = self.mock_ssm
        subject = aws_clients.SSMClient(self.logger)
        subject.get_ssm_parameter_by_name = MagicMock(return_value="random")

        self.assertTrue(subject.has_task_parameter("some param"))

    def test_has_task_parameter_returns_False_when_parater_not_found(self, mock_boto):
        mock_boto.return_value = self.mock_ssm
        subject = aws_clients.SSMClient(self.logger)
        subject.get_ssm_parameter_by_name = MagicMock(return_value=None)

        self.assertFalse(subject.has_task_parameter("some param"))

    def test_delete_task_parameter_calls_delete_parameter_with_ssm(self, mock_boto):
        mock_boto.return_value = self.mock_ssm
        subject = aws_clients.SSMClient(self.logger)

        task_name = "HELLO TASK"

        subject.delete_task_parameter(task_name)
        self.mock_ssm.delete_parameter.assert_called_once_with(Name=task_name)


@patch("aws_clients.boto3.client")
class EC2ClientTest(unittest.TestCase):
    VPC_ID = "vpc-test-id"
    INSTANCE_FILTERS = [
        {"Name": "tag:Name", "Values": ["ContainerECRScanner"]},
        {"Name": "instance-state-name", "Values": ["running"]},
        {"Name": "vpc-id", "Values": [VPC_ID]},
    ]
    SUBNET_FILTERS = [{"Name": "vpc-id", "Values": [VPC_ID]}]

    def setUp(self):
        self.logger = MagicMock()
        self.mock_ec2 = MagicMock()

    def test_get_defendername_returns_scanner_dnsname(self, mock_boto):
        dnsname = "test-dnsname"
        describe_response = {
            "Reservations": [
                {"Instances": [{"NetworkInterfaces": [{"PrivateDnsName": dnsname}]}]}
            ]
        }
        self.mock_ec2.describe_instances = MagicMock(return_value=describe_response)
        mock_boto.return_value = self.mock_ec2
        subject = aws_clients.EC2Client(self.logger)

        self.assertEqual(subject.get_defendername(self.VPC_ID), dnsname)
        self.mock_ec2.describe_instances.assert_called_once_with(
            Filters=self.INSTANCE_FILTERS
        )

    def test_get_defendername_returns_None_when_KeyError(self, mock_boto):
        self.mock_ec2.describe_instances = MagicMock(return_value={})
        mock_boto.return_value = self.mock_ec2
        subject = aws_clients.EC2Client(self.logger)

        self.assertIsNone(subject.get_defendername(self.VPC_ID))

    def test_get_subnet_id_returns_subnet_id(self, mock_boto):
        subnet_id = "test-subnet-id"
        describe_response = {
            "Subnets": [
                {
                    "AvailableIpAddressCount": 1,
                    "SubnetId": subnet_id,
                    "Tags": [{"Key": "Name", "Value": "private-name"}],
                },
                {
                    "AvailableIpAddressCount": 5,
                    "SubnetId": subnet_id,
                    "Tags": [
                        {"Key": "Team", "Value": "ma-team"},
                        {"Key": "Name", "Value": "private-name"},
                    ],
                },
            ]
        }
        self.mock_ec2.describe_subnets = MagicMock(return_value=describe_response)
        mock_boto.return_value = self.mock_ec2
        subject = aws_clients.EC2Client(self.logger)

        self.assertEqual(subject.get_subnet_id(self.VPC_ID), subnet_id)
        self.mock_ec2.describe_subnets.assert_called_once_with(
            Filters=self.SUBNET_FILTERS
        )

    def test_get_subnet_id_raises_VPCNotFound_when_no_subnet_has_more_than_4_ip_addresses(
        self, mock_boto
    ):
        subnet_id = "test-subnet-id"
        describe_response = {
            "Subnets": [
                {
                    "AvailableIpAddressCount": 1,
                    "SubnetId": subnet_id,
                    "Tags": [{"Key": "Name", "Value": "private-name"}],
                },
            ]
        }
        self.mock_ec2.describe_subnets = MagicMock(return_value=describe_response)
        mock_boto.return_value = self.mock_ec2
        subject = aws_clients.EC2Client(self.logger)

        with self.assertRaises(VPCNotFound):
            subject.get_subnet_id(self.VPC_ID)

    def test_get_subnet_id_raises_VPCNotFound_when_no_subnet_tags_with_private_name(
        self, mock_boto
    ):
        subnet_id = "test-subnet-id"
        describe_response = {
            "Subnets": [
                {
                    "AvailableIpAddressCount": 5,
                    "SubnetId": subnet_id,
                    "Tags": [{"Key": "Name", "Value": "public-name"}],
                },
            ]
        }
        self.mock_ec2.describe_subnets = MagicMock(return_value=describe_response)
        mock_boto.return_value = self.mock_ec2
        subject = aws_clients.EC2Client(self.logger)

        with self.assertRaises(VPCNotFound):
            subject.get_subnet_id(self.VPC_ID)


@patch("aws_clients.boto3.client")
class ServiceCatalogTest(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()
        self.mock_sc = MagicMock()

    def test_provisioned_product_exists_returns_True_no_error(self, mock_boto):
        product_name = "test-product-name"
        self.mock_sc.describe_provisioned_product = MagicMock()
        mock_boto.return_value = self.mock_sc

        subject = aws_clients.ServiceCatalog(self.logger)

        self.assertTrue(subject.provisioned_product_exists(product_name))
        self.mock_sc.describe_provisioned_product.assert_called_once_with(
            Name=product_name
        )

    def test_deprovision_scanner_returns_None_when_provisioned_product_not_exist(
        self, mock_boto
    ):
        product_name = "test-product-name"
        self.mock_sc.terminate_provisioned_product = MagicMock()
        mock_boto.return_value = self.mock_sc

        subject = aws_clients.ServiceCatalog(self.logger)
        subject.provisioned_product_exists = MagicMock(return_value=False)

        self.assertIsNone(subject.deprovision_scanner(product_name))
        self.mock_sc.terminate_provisioned_product.assert_called_once_with(
            ProvisionedProductName=product_name
        )

    def test_deprovision_scanner_returns_None_when_ResourceNotFoundException_but_provisioned_product_not_exist(
        self, mock_boto
    ):
        product_name = "test-product-name"
        self.mock_sc.terminate_provisioned_product.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Unit Test"}},
            "fake client error?",
        )
        mock_boto.return_value = self.mock_sc

        subject = aws_clients.ServiceCatalog(self.logger)
        subject.provisioned_product_exists = MagicMock(return_value=False)

        self.assertIsNone(subject.deprovision_scanner(product_name))

    def test_deprovision_scanner_returns_None_when_unidentified_ClientError_but_provisioned_product_not_exist(
        self, mock_boto
    ):
        product_name = "test-product-name"
        self.mock_sc.terminate_provisioned_product.side_effect = FAKE_CLIENT_ERROR

        mock_boto.return_value = self.mock_sc

        subject = aws_clients.ServiceCatalog(self.logger)
        subject.provisioned_product_exists = MagicMock(return_value=False)

        self.assertIsNone(subject.deprovision_scanner(product_name))

    @patch("aws_clients.time")
    def test_deprovision_scanner_raises_DeprovisioningScannerTimeoutError_when_exhausted(
        self,
        mock_time,
        mock_boto,
    ):
        product_name = "test-product-name"
        self.mock_sc.terminate_provisioned_product = MagicMock()
        mock_boto.return_value = self.mock_sc
        mock_time.sleep = MagicMock()

        subject = aws_clients.ServiceCatalog(self.logger)
        subject.provisioned_product_exists = MagicMock(return_value=True)

        with self.assertRaises(DeprovisioningScannerTimeoutError):
            subject.deprovision_scanner(product_name)

    def test_describe_provisioned_product_by_id_returns_provisioned_product(
        self, mock_boto
    ):
        product_id = "test-product-id"
        provisioned_product = MagicMock()
        self.mock_sc.describe_provisioned_product = MagicMock(
            return_value=provisioned_product
        )
        mock_boto.return_value = self.mock_sc

        subject = aws_clients.ServiceCatalog(self.logger)

        self.assertEqual(
            subject.describe_provisioned_product_by_id(product_id), provisioned_product
        )
        self.mock_sc.describe_provisioned_product.assert_called_once_with(Id=product_id)
