import json
import unittest
from unittest.mock import patch, MagicMock
import sys

# Add the docker subdirectory to the module search path
sys.path.append("docker")

# pylint: disable=import-error no-name-in-module
import prisma
from errors import (
    ExitContainerScanner,
    RegistrationError,
    ProvisioningTimeoutError,
    DeprovisioningScannerTimeoutError,
)

# pylint: enable=import-error no-name-in-module


class PrismaClientTest(unittest.TestCase):
    TOKEN = "fake-token"
    ECR_REGISTRY = "fake-ecr-registry"
    RETRY_POLICY = {
        "total": 3,
        "status_forcelist": {429, 501, 502, 503, 504},
        "backoff_factor": 1,
        "respect_retry_after_header": True,
    }

    def _test_api_helper(
        self,
        mock_retry,
        mock_requests,
        http_method,
        token=None,
        payload=None,
        params=None,
        status_code=200,
        api_should_fail=False,
    ):
        url = "/niceurl"

        mock_api_response = MagicMock()
        mock_api_response.status_code = status_code

        mock_session = MagicMock()
        if api_should_fail:
            mock_session.get.side_effect = Exception()
            mock_session.post.side_effect = Exception()
            mock_session.delete.side_effect = Exception()
        else:
            mock_session.get.return_value = mock_api_response
            mock_session.post.return_value = mock_api_response
            mock_session.delete.return_value = mock_api_response

        mock_requests.Session.return_value = mock_session

        if status_code == 200 and not api_should_fail:
            self.assertEqual(
                self.subject.create_prisma_api_request(
                    http_method, url, token, payload, params
                ),
                mock_api_response,
            )
        else:
            with self.assertRaises(ExitContainerScanner):
                self.subject.create_prisma_api_request(
                    http_method, url, token, payload, params
                )

        mock_retry.assert_called_once_with(**self.RETRY_POLICY)
        mock_requests.adapters.HTTPAdapter.assert_called_once_with(
            max_retries=mock_retry()
        )
        mock_session.mount.assert_called_once_with(
            "https://", mock_requests.adapters.HTTPAdapter()
        )
        if token is not None:
            self.assertTrue("Authorization" in mock_session.headers)
            self.assertTrue("content-type" not in mock_session.headers)
        else:
            self.assertTrue("Authorization" not in mock_session.headers)
            self.assertTrue("content-type" in mock_session.headers)

        full_url = self.subject.PRISMA_COMPUTE_REST_API_URL + url
        request_params = {
            "params": params,
            "data": None if payload is None else json.dumps(payload),
            "timeout": 5.0,
        }

        if http_method == "GET":
            mock_session.get.assert_called_once_with(
                full_url,
                **request_params,
            )
        elif http_method == "POST":
            mock_session.post.assert_called_once_with(
                full_url,
                **request_params,
            )
        elif http_method == "DELETE":
            mock_session.delete.assert_called_once_with(
                full_url,
                **request_params,
            )
        else:
            raise Exception(f"Not Supported http method : {http_method}")

    def setUp(self):
        self.logger = MagicMock()
        self.sts_client = MagicMock()
        self.sm_client = MagicMock()
        self.ec2_client = MagicMock()

        self.subject = prisma.PrismaClient(
            self.logger, self.sts_client, self.sm_client, self.ec2_client
        )

    def test_get_token_returns_token(self):
        role_arn_name = "fake-role-arn"
        username = "test-username"
        pswd = "test-pswd"
        aws_creds = {}
        prisma_secrets = {"prismaAccessKeyId": username, "prismaSecretKey": pswd}
        api_response = MagicMock()
        api_response.text = json.dumps({"token": self.TOKEN})

        self.sts_client.assume_role = MagicMock(return_value=aws_creds)
        self.sm_client.get_prisma_secrets = MagicMock(return_value=prisma_secrets)
        self.subject.create_prisma_api_request = MagicMock(return_value=api_response)

        self.assertEqual(self.subject.get_token(role_arn_name), self.TOKEN)
        self.sts_client.assume_role.assert_called_once_with(role_arn_name)
        self.sm_client.get_prisma_secrets.assert_called_once_with(aws_creds)
        self.subject.create_prisma_api_request.assert_called_once_with(
            "POST",
            url="/authenticate",
            payload={
                "username": prisma_secrets["prismaAccessKeyId"],
                "password": prisma_secrets["prismaSecretKey"],
            },
        )

    def test_register_ecr_registry_raises_RegistrationError_when_scanner_dnsname_None(
        self,
    ):
        with self.assertRaises(RegistrationError):
            self.subject.register_ecr_registry(self.TOKEN, "ecr-repo", None)

    @patch("prisma.sleep", return_value=None)
    def test_register_ecr_registry_calls_create_prisma_api_request_upto_max_wait_times_when_dnsname_defender_not_found(
        self, _mock_sleep
    ):
        scanner_dnsname = "fake-dnsname"
        api_response = MagicMock()
        api_response.json.return_value = {}
        self.subject.create_prisma_api_request = MagicMock(return_value=api_response)

        self.subject.register_ecr_registry(
            self.TOKEN, self.ECR_REGISTRY, scanner_dnsname
        )

        self.assertEqual(
            self.subject.create_prisma_api_request.call_count,
            self.subject.REGISTERY_MAX_WAIT_TIME + 1,  # 1 - Create Registry Request
        )

    @patch("prisma.sleep", return_value=None)
    def test_register_ecr_registry_calls_create_prisma_api_request_upto_twice_when_dnsname_defender_found(
        self, _mock_sleep
    ):
        scanner_dnsname = "fake-dnsname"
        api_response = MagicMock()
        api_response.json.return_value = {f"{scanner_dnsname}": "something"}
        self.subject.create_prisma_api_request = MagicMock(return_value=api_response)

        self.subject.register_ecr_registry(
            self.TOKEN, self.ECR_REGISTRY, scanner_dnsname
        )

        self.assertEqual(
            self.subject.create_prisma_api_request.call_count,
            1 + 1,  # 1 - Get Defender Name && 1 - Create Registry Request
        )

    def test_force_ecr_registry_scan_calls_post_api_once(self):
        self.subject.create_prisma_api_request = MagicMock()

        self.subject.force_ecr_registry_scan(self.TOKEN, self.ECR_REGISTRY)

        self.subject.create_prisma_api_request.assert_called_once_with(
            "POST",
            "/registry/scan",
            token=self.TOKEN,
            payload={"tag": {"registry": self.ECR_REGISTRY}},
        )

    def test_retrieve_scanner_results_returns_response_text(self):
        random_text = "Lorem Ipsum?"

        api_response = MagicMock()
        api_response.text = random_text

        self.subject.create_prisma_api_request = MagicMock(return_value=api_response)

        self.assertEqual(
            self.subject.retrieve_scanner_results(self.TOKEN, self.ECR_REGISTRY),
            random_text,
        )

        self.subject.create_prisma_api_request.assert_called_once_with(
            "GET",
            "/registry/download",
            token=self.TOKEN,
            params=f"registry={self.ECR_REGISTRY}",
        )

    @patch("prisma.sleep")
    def test_wait_for_scan_completion_calls_sleep_max_wait_time_minutes(
        self, mock_sleep
    ):
        one_minute = 60  # in seconds

        self.subject.wait_for_scan_completion()

        mock_sleep.assert_called_once_with(self.subject.SCAN_WAIT_TIME * one_minute)

    def test_remove_defender_calls_delete_api_once(self):
        defender_name = "fake-defender"
        self.subject.create_prisma_api_request = MagicMock()

        self.subject.remove_defender(self.TOKEN, defender_name)

        self.subject.create_prisma_api_request.assert_called_once_with(
            "DELETE", f"/defenders/{defender_name}", token=self.TOKEN
        )

    @patch("prisma.requests")
    @patch("prisma.Retry")
    def test_create_prisma_api_request_returns_response_on_successful_GET_request_with_token(
        self, mock_retry, mock_requests
    ):
        self._test_api_helper(mock_retry, mock_requests, "GET", self.TOKEN)

    @patch("prisma.requests")
    @patch("prisma.Retry")
    def test_create_prisma_api_request_returns_response_on_successful_GET_request_with_no_token(
        self, mock_retry, mock_requests
    ):
        self._test_api_helper(mock_retry, mock_requests, "GET")

    @patch("prisma.requests")
    @patch("prisma.Retry")
    def test_create_prisma_api_request_returns_response_on_successful_GET_request_with_payload(
        self, mock_retry, mock_requests
    ):
        self._test_api_helper(
            mock_retry, mock_requests, "GET", payload={"I wanna be": "The very best"}
        )

    @patch("prisma.requests")
    @patch("prisma.Retry")
    def test_create_prisma_api_request_returns_response_on_successful_POST_request_with_token(
        self, mock_retry, mock_requests
    ):
        self._test_api_helper(mock_retry, mock_requests, "POST", self.TOKEN)

    @patch("prisma.requests")
    @patch("prisma.Retry")
    def test_create_prisma_api_request_returns_response_on_successful_POST_request_with_no_token(
        self, mock_retry, mock_requests
    ):
        self._test_api_helper(mock_retry, mock_requests, "POST")

    @patch("prisma.requests")
    @patch("prisma.Retry")
    def test_create_prisma_api_request_returns_response_on_successful_POST_request_with_payload(
        self, mock_retry, mock_requests
    ):
        self._test_api_helper(
            mock_retry, mock_requests, "POST", payload={"I wanna be": "The very best"}
        )

    @patch("prisma.requests")
    @patch("prisma.Retry")
    def test_create_prisma_api_request_returns_response_on_successful_DELETE_request_with_token(
        self, mock_retry, mock_requests
    ):
        self._test_api_helper(mock_retry, mock_requests, "DELETE", self.TOKEN)

    @patch("prisma.requests")
    @patch("prisma.Retry")
    def test_create_prisma_api_request_returns_response_on_successful_DELETE_request_with_no_token(
        self, mock_retry, mock_requests
    ):
        self._test_api_helper(mock_retry, mock_requests, "DELETE", params="Some param")

    @patch("prisma.requests")
    @patch("prisma.Retry")
    def test_create_prisma_api_request_returns_response_on_successful_DELETE_request_with_payload(
        self, mock_retry, mock_requests
    ):
        self._test_api_helper(
            mock_retry, mock_requests, "DELETE", payload={"I wanna be": "The very best"}
        )

    @patch("prisma.requests")
    @patch("prisma.Retry")
    def test_create_prisma_api_request_raises_ExitContainerScanner_on_successful_api_request_but_non_200_status(
        self, mock_retry, mock_requests
    ):
        self._test_api_helper(mock_retry, mock_requests, "DELETE", status_code=404)

    @patch("prisma.requests")
    @patch("prisma.Retry")
    def test_create_prisma_api_request_raises_ExitContainerScanner_on_api_failure(
        self, mock_retry, mock_requests
    ):
        self._test_api_helper(mock_retry, mock_requests, "GET", api_should_fail=True)


class ScannerTest(unittest.TestCase):
    def _create_csv_dict(
        self, problem="test-problem", severity=None, cve_id="test-cve-id"
    ):
        base_dict = {
            "Registry": "xxxxxxxxx.dkr.ecr.us-east-1.amazonaws.com",
            "Repository": "testscan",
            "Tag": "latest",
            "Id": "xxxxxxxxx.dkr.ecr.us-east-1.amazonaws.com/testscan:latest",
            "Distro": "debian-stretch",
            "Hostname": "ip-xxxxxxxx.ec2.internal",
            "Layer": "",
            "CVE ID": cve_id,
            "Vulnerability ID": 411,
            "Type": "product",
            "Packages": problem,
            "Source Package": "",
            "Package Version": "2.0.0",
            "Package License": "",
            "CVSS": "7.50",
            "Fix Status": "",
            "Risk Factors": '"Attack complexity: low, Attack vector: network, DoS, High severity"',
            "Vulnerability Tags": "",
            "Description": "Microsoft .NET Framework 2.0 has risk",
            "Cause": "",
            "Custom Labels": "",
            "Published": "2018-01-10 01:29:00.000",
        }
        if severity is not None:
            base_dict["Severity"] = severity

        return base_dict

    def setUp(self):
        self.logger = MagicMock()
        self.s3_client = MagicMock()
        self.sc_client = MagicMock()
        self.ssm_client = MagicMock()
        self.prisma_client = MagicMock()

        self.subject = prisma.Scanner(
            self.logger,
            self.s3_client,
            self.sc_client,
            self.ssm_client,
            self.prisma_client,
        )

    @patch("prisma.StringIO")
    @patch("prisma.csv")
    @patch("prisma.open")
    @patch("prisma.os")
    def test_save_scanner_results_calls_s3_client_function(
        self, _mock_os, _mock_open, mock_csv, _mock_io
    ):
        mock_csv.reader.return_value = [""]

        self.subject.save_scanner_results("")

        self.s3_client.upload_file.assert_called_once()

    @patch("prisma.csv")
    def test_evaluate_scanner_results_saves_securityhub_findings(self, mock_csv):
        csv_dicts = [
            self._create_csv_dict(severity="high"),
            self._create_csv_dict(severity="critical", cve_id=""),
        ]

        mock_csv.DictReader.return_value = csv_dicts

        mock_finding = MagicMock()

        mock_handle = MagicMock()
        mock_handle.Finding.return_value = mock_finding

        self.subject.evaluate_scanner_results(mock_handle, "")

        self.assertEqual(mock_finding.save.call_count, len(csv_dicts))

    @patch("prisma.csv")
    def test_evaluate_scanner_results_saves_securityhub_findings_in_groups_of_problem(
        self, mock_csv
    ):
        csv_dicts = [
            # Group 1 (test-package vuln)
            self._create_csv_dict(problem="test-package", severity="high"),
            self._create_csv_dict(problem="test-package", severity="critical"),
            # Group 2 (other-package vuln)
            self._create_csv_dict(problem="other-package", severity="high"),
            self._create_csv_dict(problem="other-package", severity="critical"),
            # Group 3 (Compliance)
            self._create_csv_dict(problem="test-package", severity="high", cve_id=""),
            self._create_csv_dict(
                problem="test-package", severity="critical", cve_id=""
            ),
        ]

        mock_csv.DictReader.return_value = csv_dicts

        mock_finding = MagicMock()

        mock_handle = MagicMock()
        mock_handle.Finding.return_value = mock_finding

        self.subject.evaluate_scanner_results(mock_handle, "")

        self.assertEqual(mock_finding.save.call_count, 3)

    @patch("prisma.csv")
    def test_evaluate_scanner_results_saves_only_higher_severity(self, mock_csv):
        csv_dicts = [
            self._create_csv_dict(problem="test-package"),
            self._create_csv_dict(problem="test-package", severity="medium"),
            self._create_csv_dict(problem="test-package", severity=""),
        ]

        mock_csv.DictReader.return_value = csv_dicts

        mock_finding = MagicMock()

        mock_handle = MagicMock()
        mock_handle.Finding.return_value = mock_finding

        self.subject.evaluate_scanner_results(mock_handle, "")

        self.assertEqual(mock_finding.save.call_count, 0)

    @patch("prisma.csv")
    def test_evaluate_scanner_results_not_raise_on_finding_save_exception(
        self, mock_csv
    ):
        csv_dicts = [
            self._create_csv_dict(severity="high"),
            self._create_csv_dict(problem="package1", severity="high"),
        ]

        mock_csv.DictReader.return_value = csv_dicts

        mock_finding = MagicMock()
        mock_finding.save.side_effect = Exception()

        mock_handle = MagicMock()
        mock_handle.Finding.return_value = mock_finding

        self.subject.evaluate_scanner_results(mock_handle, "")

        self.assertEqual(mock_finding.save.call_count, 2)

    @patch("prisma.datetime")
    @patch("prisma.os")
    def test_generate_informational_finding_saves_securityhub_finding(
        self, _mock_os, mock_datetime
    ):
        region = "us-west-2"
        fmt_utcnow = "1234"

        mock_datetime.utcnow.strftime.return_value = fmt_utcnow

        mock_finding = MagicMock()

        mock_handle = MagicMock()
        mock_handle.aws_region.return_value = region
        mock_handle.Finding.return_value = mock_finding

        self.subject.generate_informational_finding(mock_handle)

        self.assertIsNotNone(mock_finding.Title)
        self.assertIsNotNone(mock_finding.Compliance)
        self.assertIsNotNone(mock_finding.Description)
        self.assertIsNotNone(mock_finding.GeneratorId)
        self.assertIsNotNone(mock_finding.LastObservedAt)

        mock_finding.save.assert_called_once()

    @patch("prisma.datetime")
    @patch("prisma.os")
    def test_generate_informational_finding_not_raise_on_finding_save_exception(
        self, _mock_os, mock_datetime
    ):
        region = "us-west-2"
        fmt_utcnow = "1234"

        mock_datetime.utcnow.strftime.return_value = fmt_utcnow

        mock_finding = MagicMock()
        mock_finding.save.side_effect = Exception()

        mock_handle = MagicMock()
        mock_handle.aws_region.return_value = region
        mock_handle.Finding.return_value = mock_finding

        self.subject.generate_informational_finding(mock_handle)

        self.assertIsNotNone(mock_finding.Title)
        self.assertIsNotNone(mock_finding.Compliance)
        self.assertIsNotNone(mock_finding.Description)
        self.assertIsNotNone(mock_finding.GeneratorId)
        self.assertIsNotNone(mock_finding.LastObservedAt)

        mock_finding.save.assert_called_once()

    def test_remove_not_calls_any_clients_if_params_None(self):
        self.subject.remove(
            provisioned_product_name=None,
            task_name=None,
            prisma_token=None,
            defender_name=None,
        )

        self.assertEqual(self.sc_client.provisioned_product_exists.call_count, 0)
        self.assertEqual(self.sc_client.deprovision_scanner.call_count, 0)

        self.assertEqual(self.ssm_client.has_task_parameter.call_count, 0)
        self.assertEqual(self.ssm_client.delete_task_parameter.call_count, 0)

        self.assertEqual(self.prisma_client.remove_defender.call_count, 0)

    def test_remove_calls_sc_client_function_when_product_name_not_None_and_product_does_not_exist(
        self,
    ):
        product_name = "test-product-name"
        self.sc_client.provisioned_product_exists = MagicMock(return_value=False)
        self.subject.remove(
            provisioned_product_name=product_name,
            task_name=None,
            prisma_token=None,
            defender_name=None,
        )

        self.sc_client.provisioned_product_exists.assert_called_once_with(product_name)
        self.assertEqual(self.sc_client.deprovision_scanner.call_count, 0)

        self.assertEqual(self.ssm_client.has_task_parameter.call_count, 0)
        self.assertEqual(self.ssm_client.delete_task_parameter.call_count, 0)

        self.assertEqual(self.prisma_client.remove_defender.call_count, 0)

    def test_remove_calls_sc_client_functions_when_product_name_not_None_and_product_does_exist(
        self,
    ):
        product_name = "test-product-name"
        self.sc_client.provisioned_product_exists = MagicMock(return_value=True)
        self.subject.remove(
            provisioned_product_name=product_name,
            task_name=None,
            prisma_token=None,
            defender_name=None,
        )

        self.sc_client.provisioned_product_exists.assert_called_once_with(product_name)
        self.sc_client.deprovision_scanner.assert_called_once_with(product_name)

        self.assertEqual(self.ssm_client.has_task_parameter.call_count, 0)
        self.assertEqual(self.ssm_client.delete_task_parameter.call_count, 0)

        self.assertEqual(self.prisma_client.remove_defender.call_count, 0)

    def test_remove_calls_ssm_client_function_when_task_name_not_None_and_parameter_does_not_exist(
        self,
    ):
        task_name = "test-task-name"
        self.ssm_client.has_task_parameter = MagicMock(return_value=False)
        self.subject.remove(
            provisioned_product_name=None,
            task_name=task_name,
            prisma_token=None,
            defender_name=None,
        )

        self.assertEqual(self.sc_client.provisioned_product_exists.call_count, 0)
        self.assertEqual(self.sc_client.deprovision_scanner.call_count, 0)

        self.ssm_client.has_task_parameter.assert_called_once_with(task_name)
        self.assertEqual(self.ssm_client.delete_task_parameter.call_count, 0)

        self.assertEqual(self.prisma_client.remove_defender.call_count, 0)

    def test_remove_calls_ssm_client_functions_when_task_name_not_None_and_parameter_does_exist(
        self,
    ):
        task_name = "test-task-name"
        self.ssm_client.has_task_parameter = MagicMock(return_value=True)
        self.subject.remove(
            provisioned_product_name=None,
            task_name=task_name,
            prisma_token=None,
            defender_name=None,
        )

        self.assertEqual(self.sc_client.provisioned_product_exists.call_count, 0)
        self.assertEqual(self.sc_client.deprovision_scanner.call_count, 0)

        self.ssm_client.has_task_parameter.assert_called_once_with(task_name)
        self.ssm_client.delete_task_parameter.assert_called_once_with(task_name)

        self.assertEqual(self.prisma_client.remove_defender.call_count, 0)

    def test_remove_calls_prisma_client_functions_when_defender_name_not_None(self):
        defender_name = "test-defender-name"
        prisma_token = "test-token"
        self.subject.remove(
            provisioned_product_name=None,
            task_name=None,
            prisma_token=prisma_token,
            defender_name=defender_name,
        )

        self.assertEqual(self.sc_client.provisioned_product_exists.call_count, 0)
        self.assertEqual(self.sc_client.deprovision_scanner.call_count, 0)

        self.assertEqual(self.ssm_client.has_task_parameter.call_count, 0)
        self.assertEqual(self.ssm_client.delete_task_parameter.call_count, 0)

        self.prisma_client.remove_defender.assert_called_once_with(
            prisma_token, defender_name
        )
