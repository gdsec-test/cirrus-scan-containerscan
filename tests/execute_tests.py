import unittest
from unittest.mock import mock_open, patch, MagicMock, PropertyMock
import sys

# Add the docker subdirectory to the module search path
sys.path.append("docker")

import execute


class execute_tests(unittest.TestCase):
    @patch("execute.log")
    @patch("datetime.datetime")
    def test_generate_informational(self, mock_datetime, mock_log):
        """generate_informational_finding()"""

        NOW = "NOW"
        mock_datetime.utcnow.return_value.strftime.return_value = NOW

        mock_handle = MagicMock()
        mock_finding = MagicMock()
        mock_finding.ProductFields = {}
        mock_handle.Finding.return_value = mock_finding

        SCOPE = "unit-test"

        execute.generate_informational_finding(mock_handle, SCOPE)

        mock_handle.Finding.assert_called_once_with("portscan/complete/" + SCOPE)
        self.assertEqual(
            mock_finding.ProductFields,
            {"Environment": "UNKNOWN", "TaskUuid": "UNKNOWN", "TeamName": "UNKNOWN"},
        )
        self.assertEqual(
            mock_finding.Title, SCOPE + " portscan: finished scan at " + NOW
        )
        self.assertEqual(mock_finding.Compliance, {"Status": "PASSED"})
        self.assertEqual(mock_finding.Description, "No description available.")
        self.assertEqual(mock_finding.GeneratorId, "portscan")
        mock_finding.save.assert_called_once_with()

    def test_test_compliance(self):
        """test_compliance()"""

        # Data without a severity member raises an exception
        with self.assertRaises(KeyError):
            result = execute.test_compliance({})

        # Severities below (or equal to) the cutoff should pass
        self.assertEqual("PASS", execute.test_compliance({"severity": {50: 1}}, 50))

        # Severities above the cutoff should fail
        self.assertEqual("FAIL", execute.test_compliance({"severity": {50: 1}}, 49))

        # A mix of severities should fail (regardless of order)
        self.assertEqual(
            "FAIL", execute.test_compliance({"severity": {49: 1, 51: 1}}, 50)
        )
        self.assertEqual(
            "FAIL", execute.test_compliance({"severity": {51: 1, 49: 1}}, 50)
        )

    @patch("execute.log")
    @patch("wrapper.put_status")
    @patch("execute.test_compliance")
    @patch("wrapper.get_exception_rules")
    @patch("wrapper.get_parameters")
    @patch("common.securityhub.SecurityHub_Manager")
    @patch("execute.generate_informational_finding")
    def test_main_aws(
        self,
        mock_info,
        mock_hub,
        mock_params,
        mock_rules,
        mock_test,
        mock_status,
        mock_log,
    ):
        """main(), source is aws"""

        DATA_DICT = {"severity": {0: 1}}

        mock_handle = MagicMock()
        mock_hub.return_value = mock_handle
        mock_handle.get_finding_data.return_value = DATA_DICT

        SCOPE = "unit-test"
        PARAMS_DICT = {
            "scope": SCOPE,
            "servicenow_instance": "test",
            "source": "aws",
            "openport_severity": 42,
        }

        # Typical basic invocation should do all the right things
        mock_params.return_value = PARAMS_DICT
        mock_rules.return_value = []
        mock_test.return_value = "TEST"

        execute.main()

        # No remote provisioning because source is "aws"
        # TODO: Execute scanner
        # TODO: Retrieve scanner results
        # No deprovisioning because no provisioning
        mock_log.error.assert_not_called()
        mock_hub.assert_called_once_with(exception_rules=[])
        mock_handle.begin_transaction.assert_called_once_with(
            scope_prefix="portscan/" + SCOPE + "/"
        )
        # TODO: Create findings for all nonconformances
        mock_info.assert_called_once_with(mock_handle, SCOPE)
        mock_handle.end_transaction.assert_called_once_with(autoarchive=True)
        mock_handle.get_finding_data.assert_called_once_with()
        mock_test.assert_called_once_with(DATA_DICT)
        mock_status.assert_called_once_with(
            {"status": "SUCCESS", "compliance": "TEST", "finding_data": DATA_DICT}
        )

    @patch("execute.log")
    @patch("wrapper.put_status")
    @patch("wrapper.get_parameters")
    @patch("common.securityhub.SecurityHub_Manager")
    def test_main_badsource(self, mock_hub, mock_params, mock_status, mock_log):
        """main(), source is unrecognized"""

        SCOPE = "unit-test"
        SOURCE = "BOGUS"
        PARAMS_DICT = {
            "scope": SCOPE,
            "servicenow_instance": "test",
            "source": SOURCE,
            "openport_severity": 42,
        }

        # Unrecognized source should abort early without doing much
        mock_params.return_value = PARAMS_DICT

        execute.main()

        mock_log.error.assert_called_once_with("Unrecognized source zone %s", SOURCE)
        mock_status.assert_called_once_with(
            {"status": "FAILED", "comment": "Unrecognized source " + SOURCE}
        )
        # No remote provisioning because we should have aborted
        # TODO: Execute scanner (not called because we aborted)
        mock_hub.assert_not_called()
