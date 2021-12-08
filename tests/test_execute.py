import unittest
from unittest.mock import patch, MagicMock
import sys

# Add the docker subdirectory to the module search path
sys.path.append("docker")

# pylint: disable=import-error no-name-in-module
import execute
from errors import ExitContainerScanner

# pylint: enable=import-error no-name-in-module


class GetAuditRoleArnTest(unittest.TestCase):
    AUDIT_ROLE_ARN = "arn:aws:iam::{}:role/GD-AuditFramework-SecretsManagerReadOnlyRole"

    def setUp(self):
        self.ssm = MagicMock()

    def _execute_validation(self, org_type, account_id):
        self.ssm.get_org_type = MagicMock(return_value=org_type)
        self.assertEqual(
            execute.get_audit_role_arn(self.ssm),
            self.AUDIT_ROLE_ARN.format(account_id),
        )

    def test_should_work_with_pci_org_type(self):
        pci_org_type = "pci"
        pci_account_id = "339078146124"
        self._execute_validation(pci_org_type, pci_account_id)

    def test_should_work_with_registry_org_type(self):
        registry_org_type = "registry"
        registry_account_id = "906957162968"
        self._execute_validation(registry_org_type, registry_account_id)

    def test_should_work_with_random_org_type(self):
        random_org_type = "somethingrandom"
        random_account_id = "672751022979"
        self._execute_validation(random_org_type, random_account_id)


@patch("execute.wrapper")
@patch("execute.securityhub")
@patch("execute.Scanner")
@patch("execute.PrismaClient")
@patch("execute.os")
@patch("execute.get_audit_role_arn")
@patch("execute.EC2Client")
@patch("execute.ECRClient")
@patch("execute.SSMClient")
@patch("execute.SecretsManagerClient")
@patch("execute.SecurityTokenServiceClient")
@patch("execute.ServiceCatalog")
@patch("execute.S3Client")
@patch("execute.boto3")
class MainTest(unittest.TestCase):
    def test_main_not_raise_with_ExitContainerScanner(
        self,
        _mock_boto3,
        _mock_s3_client,
        _mock_sc_client,
        _mock_sts_client,
        _mock_asm_client,
        _mock_ssm_client,
        _mock_ecr_client,
        _mock_ec2_client,
        mock_get_audit_role_arn,
        _mock_os,
        _mock_prisma_client,
        _mock_scanner,
        _mock_securityhub,
        _mock_wrapper,
    ):
        mock_get_audit_role_arn.side_effect = ExitContainerScanner()
        self.assertIsNone(execute.main())

    def test_main_not_call_scanner_remove_when_scanner_None(
        self,
        _mock_boto3,
        _mock_s3_client,
        _mock_sc_client,
        _mock_sts_client,
        _mock_asm_client,
        _mock_ssm_client,
        _mock_ecr_client,
        _mock_ec2_client,
        mock_get_audit_role_arn,
        _mock_os,
        _mock_prisma_client,
        mock_scanner,
        _mock_securityhub,
        _mock_wrapper,
    ):
        mock_get_audit_role_arn.side_effect = ExitContainerScanner()

        self.assertIsNone(execute.main())
        self.assertEqual(mock_scanner.remove.call_count, 0)

    def test_main_not_raise_with_Exception(
        self,
        _mock_boto3,
        _mock_s3_client,
        _mock_sc_client,
        _mock_sts_client,
        _mock_asm_client,
        mock_ssm_client,
        _mock_ecr_client,
        _mock_ec2_client,
        _mock_get_audit_role_arn,
        _mock_os,
        _mock_prisma_client,
        _mock_scanner,
        _mock_securityhub,
        _mock_wrapper,
    ):
        mock_client = MagicMock()
        mock_client.get_vpc_id.side_effect = Exception()

        mock_ssm_client.return_value = mock_client
        self.assertIsNone(execute.main())

    def test_main_calls_prisma_client_if_not_provisioned_and_has_ecr_repositories(
        self,
        _mock_boto3,
        _mock_s3_client,
        _mock_sc_client,
        _mock_sts_client,
        _mock_asm_client,
        mock_ssm_client,
        mock_ecr_client,
        _mock_ec2_client,
        _mock_get_audit_role_arn,
        _mock_os,
        mock_prisma_client,
        _mock_scanner,
        _mock_securityhub,
        _mock_wrapper,
    ):
        mock_ssm = MagicMock()
        mock_ssm.has_task_parameter.return_value = False

        mock_ecr = MagicMock()
        mock_ecr.has_repositories.return_value = True

        mock_prisma = MagicMock()

        mock_ssm_client.return_value = mock_ssm
        mock_ecr_client.return_value = mock_ecr
        mock_prisma_client.return_value = mock_prisma

        self.assertIsNone(execute.main())
        mock_prisma.get_token.assert_called_once()

    def test_main_not_call_prisma_client_if_provisioned_and_has_ecr_repositories(
        self,
        _mock_boto3,
        _mock_s3_client,
        _mock_sc_client,
        _mock_sts_client,
        _mock_asm_client,
        mock_ssm_client,
        mock_ecr_client,
        _mock_ec2_client,
        _mock_get_audit_role_arn,
        _mock_os,
        mock_prisma_client,
        _mock_scanner,
        _mock_securityhub,
        _mock_wrapper,
    ):
        mock_ssm = MagicMock()
        mock_ssm.has_task_parameter.return_value = True

        mock_ecr = MagicMock()
        mock_ecr.has_repositories.return_value = True

        mock_prisma = MagicMock()

        mock_ssm_client.return_value = mock_ssm
        mock_ecr_client.return_value = mock_ecr
        mock_prisma_client.return_value = mock_prisma

        self.assertIsNone(execute.main())
        self.assertEqual(mock_prisma.get_token.call_count, 0)
