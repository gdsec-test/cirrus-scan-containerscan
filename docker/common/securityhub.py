#!/usr/bin/env python3
"""AWS Security Hub helper module"""
# pylint: disable=bad-continuation

import copy
import datetime
import json
import logging
import re

import boto3

log = logging.getLogger(__name__)  # pylint: disable=invalid-name

# For consolidation purposes, send Security Hub findings to a fixed, predefined
# region regardless of which region the client is operating in, and regardless
# of which region(s) contain any detected findings. This fixed region must be
# specified when creating the boto3 securityhub service client, and it must be
# specified in the ProductArn for any findings to be imported.
SECURITY_HUB_REGION = "us-west-2"

# These are used in several places below for autoarchiving. It should be
# safe to change them (at the risk of accumulating cruft) since strict
# consistency is required only for the span of a single program execution.
ARCHIVE_KEY = "archive_reason"
ARCHIVE_VALUE = "no longer detected"


class Finding:  # pylint: disable=too-many-instance-attributes
    """Encapsulated SecurityHub Finding"""

    ALLOWED_FIELDS = (
        "SchemaVersion",
        "Id",
        "ProductArn",
        "GeneratorId",
        "AwsAccountId",
        "Types",
        "FirstObservedAt",
        "LastObservedAt",
        "CreatedAt",
        "UpdatedAt",
        "Severity",
        "Confidence",
        "Criticality",
        "Title",
        "Description",
        "Remediation",
        "SourceUrl",
        "ProductFields",
        "UserDefinedFields",
        "Malware",
        "Network",
        "Process",
        "ThreatIntelIndicators",
        "Resources",
        "Compliance",
        "VerificationState",
        "Workflow",
        "WorkflowState",  # Deprecated by AWS 13 March 2020
        "RecordState",
        "RelatedFindings",
        "Note",
    )

    def __init__(
        self,
        manager,
        finding_id=None,
        override_dict=None,
        default_dict=None,
        merge=False,
    ):
        """Initialize a Security Hub finding"""

        self._manager = manager

        # Security Hub findings format
        # https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
        self._finding = {}
        self._setbyuser = set()
        self._isnew = True

        # Attempt to load an existing Security Hub finding if finding_id given
        if finding_id:
            result = self._manager.get_finding(finding_id)

            if result:
                self._finding = result
                self._isnew = False
            else:
                self._finding["Id"] = finding_id

        # Populate attributes from a supplied dictionary if given. This set
        # overrides any existing attributes, except we attempt to cleverly
        # merge dict and list attributes when merge is True.
        if override_dict:
            for key in override_dict:
                if key in Finding.ALLOWED_FIELDS:
                    if merge and key in self._finding:
                        # Potentially merge multi-valued content
                        if isinstance(self._finding[key], dict):
                            # Dictionary: add/replace user-specified members
                            self._finding[key].update(override_dict[key])
                        elif isinstance(self._finding[key], list):
                            # List: add members that are not already present
                            # and preserve order
                            self._finding[key].extend(
                                [
                                    member
                                    for member in override_dict[key]
                                    if member not in self._finding[key]
                                ]
                            )
                        else:
                            # Simple attributes can't be merged; overwrite
                            self._finding[key] = override_dict[key]
                    else:
                        # Set content absolutely (replacing any prior data)
                        self._finding[key] = override_dict[key]
                    self._setbyuser.add(key)

        # Similarly, we can define default attributes (which are set
        # only if they are missing)
        if default_dict:
            for key in default_dict:
                if key in Finding.ALLOWED_FIELDS and key not in self._finding:
                    self._finding[key] = default_dict[key]

        # If "RelatedFindings" is an empty list, remove it because the import
        # will fail with an empty list?!
        if (
            "RelatedFindings" in self._finding
            and self._finding["RelatedFindings"] == []
        ):
            del self._finding["RelatedFindings"]

        # Populate required fields if they're not present
        utcnow = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        for key, value in {
            "AwsAccountId": self._manager.aws_account(),
            "SchemaVersion": "2018-10-08",
            "CreatedAt": utcnow,
            "UpdatedAt": utcnow,
            "RecordState": "ACTIVE",
            "Workflow": {"Status": "NEW"},
            "GeneratorId": "generator_id",
            "Compliance": {"Status": "FAILED"},
            "Severity": {"Normalized": 0, "Product": 0.0},
            "Types": ["Software and Configuration Checks/GoDaddy Cirrus Scan"],
            "ProductArn": "arn:aws:securityhub:%s:%s:product/%s/default"
            % (
                SECURITY_HUB_REGION,
                self._manager.aws_account(),
                self._manager.aws_account(),
            ),
            "ProductFields": {"CompanyName": "GoDaddy", "ProductName": "Cirrus Scan"},
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": "AWS::::Account:%s" % self._manager.aws_account(),
                    "Partition": "aws",
                    "Region": self._manager.aws_region(),
                }
            ],
        }.items():

            if key not in self._finding:
                self._finding[key] = value
            elif isinstance(value, dict) and isinstance(self._finding[key], dict):
                # Define (only) missing elements in existing dictionaries
                for subkey in value:
                    if subkey not in self._finding[key]:
                        self._finding[key][subkey] = value[subkey]
            # To reflect on... Should lists have special treatment also,
            # and if so, what is the proper behavior?

    def __getattr__(self, k):
        return self._finding.get(k, None)

    def __setattr__(self, k, v):
        if k == "Id" and k in self._finding and v != self._finding[k]:
            raise ValueError("identifier is read-only")
        if k in Finding.ALLOWED_FIELDS:
            self._finding[k] = v
            self._setbyuser.add(k)
        else:
            super().__setattr__(k, v)

    def to_dict(self):
        """Return a dict of the finding's attributes"""

        return self._finding

    def is_new(self):
        """Report whether this finding is new or existed previously"""

        return self._isnew

    def _validate_attributes(self):
        """Ensure attributes are consistent"""

        # Some attributes must exist for a finding to be valid
        for key in ("Id", "Title", "Description"):
            if key not in self._finding:
                log.error("Missing required finding attribute: %s", key)

        # SecurityHub generates a severity label automatically, but does not
        # update it if the severity changes. Detect this case and force label to
        # be regenerated so severity and label are always consistent.
        if (
            "Severity" in self._setbyuser
            and "ProductFields" in self._finding
            and "aws/securityhub/SeverityLabel" in self._finding["ProductFields"]
        ):
            del self._finding["ProductFields"]["aws/securityhub/SeverityLabel"]

    def _update_state(self):
        """Maintain timestamp attributes"""

        # Modify fields for update scenario
        utcnow = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        self._finding["UpdatedAt"] = utcnow
        if "CreatedAt" not in self._finding:
            self._finding["CreatedAt"] = utcnow
        if "LastObservedAt" in self._finding and "FirstObservedAt" not in self._finding:
            self._finding["FirstObservedAt"] = self._finding["LastObservedAt"]

    def _handle_finding_exception(self):
        """Check for an approved exception"""

        # Adjust title and severity for approved exceptions
        if (
            self._finding.get("UserDefinedFields", {}).get("exception_status", None)
            == "approved"
        ):
            # Retrieve expiration date:
            # If not present, assume a future date so the exception is considered valid
            # If parsing error, assume an earlier date so that the exception is removed
            expiration_str = self._finding["UserDefinedFields"].get(
                "exception_expiration", "2099-12-31"
            )
            try:
                exception_expiration = datetime.datetime.strptime(
                    expiration_str, "%Y-%m-%d"
                )
            except ValueError:
                log.error(
                    "Invalid expiration date for finding (%s): %s",
                    self._finding["Id"],
                    expiration_str,
                )
                exception_expiration = datetime.datetime(2000, 1, 1)

            if datetime.datetime.today() < exception_expiration:
                log.debug("Finding has an approved exception")
                self._finding["Severity"] = {"Normalized": 0, "Product": 0.0}
                if not self._finding["Title"].endswith(" [exception]"):
                    self._finding["Title"] += " [exception]"

                # This sucks, but since this is not an explicit user-directed
                # severity change and anyway that check already was made, we
                # must (again) maintain label consistency explicitly.
                if (
                    "ProductFields" in self._finding
                    and "aws/securityhub/SeverityLabel"
                    in self._finding["ProductFields"]
                ):
                    del self._finding["ProductFields"]["aws/securityhub/SeverityLabel"]

            else:
                log.info(
                    "Removing exception expiration for finding (%s)",
                    self._finding["Id"],
                )
                for key in list(self._finding.get("UserDefinedFields", {})):
                    if key.startswith("exception_"):
                        del self._finding["UserDefinedFields"][key]

        # If "UserDefinedFields" is an empty dict, remove it
        if (
            "UserDefinedFields" in self._finding
            and self._finding["UserDefinedFields"] == {}
        ):
            del self._finding["UserDefinedFields"]

    def _import_finding(self):
        """Import Security Hub finding"""

        log.debug("Importing Security Hub finding: %s", json.dumps(self._finding))
        self._manager.put_finding(self._finding)

    def rename(self, new_finding_id):
        """Change the finding_id of a finding"""

        # Our Quixotic goal is to fix a mis-named finding without losing either
        # old configuration data or updates made by the caller prior to now.

        # Retrieve "old-new" state (current state under new name)
        new_baseline = self._manager.get_finding(new_finding_id)

        # If the new finding doesn't exist, just change id and we're done
        if new_baseline is None:
            self._finding["Id"] = new_finding_id
            self._setbyuser.add("Id")
            return

        # Merge. Precedence (from highest to lowest) is:
        # 1. User changes (keys in self._setbyuser, data in self._finding)
        # 2. Old data in named finding (in new_baseline)
        # 3. Old data (probably inherited defaults) (in self._finding)
        for k in new_baseline:
            if k not in self._setbyuser:
                self._finding[k] = new_baseline[k]
        self._finding["Id"] = new_finding_id
        self._setbyuser.add("Id")
        self._isnew = False

    def save(self):
        """Update Security Hub finding by reimporting it"""

        self._validate_attributes()
        self._update_state()
        self._handle_finding_exception()
        self._import_finding()


class SecurityHub_Manager:  # pylint: disable=too-many-instance-attributes,invalid-name
    """Wrapper for AWS Session() and extended SecurityHub semantics"""

    def __init__(self, scope_prefix=None, scope_region=None, **kwargs):
        self._session = None  # AWS Session object
        self._securityhub = None  # AWS SecurityHub object
        self._prefix = scope_prefix  # User-supplied finding ID prefix
        self._region = scope_region  # User-supplied target region
        self._cache = {}  # In-mem finding cache
        self._in_transaction = False  # Are we buffering updates?
        self._dirty = False  # No changes made (yet)
        self._imported_ids = set()  # Finding IDs imported in transaction
        self._account = None  # AWS account
        self._demographics = None  # End-of-transaction finding summary
        self._began_transaction = None  # When did transaction begin?

        self.new_session(**kwargs)  # Set up all context

    def Finding(
        self, finding_id=None, override_dict=None, default_dict=None, merge=False
    ):
        """Finding associated with this session"""

        return Finding(
            finding_id=finding_id,
            override_dict=override_dict,
            default_dict=default_dict,
            merge=merge,
            manager=self,
        )

    def _load_cache(self, batch_size=100):
        """Cache all SecurityHub findings with matching prefix"""

        self._cache = {}  # key: id, value: finding

        aws_filters = {
            "Id": [{"Comparison": "PREFIX", "Value": self._prefix}],
            "AwsAccountId": [{"Comparison": "EQUALS", "Value": self.aws_account()}],
            "RecordState": [{"Comparison": "EQUALS", "Value": "ACTIVE"}],
        }
        if self._region is not None:
            aws_filters["ResourceRegion"] = [
                {"Comparison": "EQUALS", "Value": self._region}
            ]

        result = self._securityhub.get_findings(
            MaxResults=batch_size, Filters=aws_filters
        )
        while result:
            for f in result["Findings"]:
                self._cache[f["Id"]] = f
            result = (
                self._securityhub.get_findings(
                    MaxResults=batch_size,
                    NextToken=result["NextToken"],
                    Filters=aws_filters,
                )
                if "NextToken" in result
                else None
            )

        self._dirty = False
        log.info("cached %i findings for prefix %s", len(self._cache), self._prefix)

    def _load_one(self, finding_id):
        """Attempt to load one finding into cache"""

        aws_filters = {
            "Id": [{"Value": finding_id, "Comparison": "EQUALS"}],
            "AwsAccountId": [{"Comparison": "EQUALS", "Value": self.aws_account()}],
            "RecordState": [{"Comparison": "EQUALS", "Value": "ACTIVE"}],
        }

        result = self._securityhub.get_findings(Filters=aws_filters)["Findings"]

        if result:
            self._cache[finding_id] = result[0]
            return result[0]
        return None

    def _mark_unmodified_findings(self, dont_archive=None):
        """Mark unmodified findings as archived"""

        # We should modify all cached findings that have not been updated
        # by the caller during this transaction, which are not already
        # archived.
        stale_ids = set(self._cache.keys()) - self._imported_ids

        # dont_archive is a list of regular expressions that specify findings
        # we do not want to autoarchive under any circumstances. All matching
        # findings in the stale set should be removed from it.
        if stale_ids and dont_archive is not None:

            # Construct a single regex equivalent to the input list
            full_pattern = ""
            for user_regex in dont_archive:
                full_pattern += "|" + user_regex
            full_regex = re.compile(full_pattern[1:])

            # Test every member of stale_ids and note all matches
            ignored_ids = set()
            for finding_id in stale_ids:
                if full_regex.search(finding_id) is not None:
                    ignored_ids.add(finding_id)

            # If findings should be retained, remove them from stale set
            if ignored_ids:
                stale_ids.difference_update(ignored_ids)
                log.info(
                    "retaining %i unmodified findings: %s",
                    len(ignored_ids),
                    json.dumps(list(ignored_ids)),
                )
            else:
                log.info("no unmodified findings matched exclusion filters.")

        # If we still have findings to autoarchive, update each of them
        if stale_ids:
            utcnow = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            fixed = []
            for finding_id in stale_ids:
                if self._cache[finding_id]["RecordState"] == "ACTIVE":
                    if "UserDefinedFields" not in self._cache[finding_id]:
                        self._cache[finding_id]["UserDefinedFields"] = {}
                    self._cache[finding_id]["UserDefinedFields"][
                        ARCHIVE_KEY
                    ] = ARCHIVE_VALUE
                    self._cache[finding_id]["RecordState"] = "ARCHIVED"
                    self._cache[finding_id]["Compliance"] = {"Status": "PASSED"}
                    # If UpdatedAt isn't revised, other changes are ignored
                    self._cache[finding_id]["UpdatedAt"] = utcnow
                    fixed.append(finding_id)
            if fixed:
                self._demographics["kind"]["archived"] = len(fixed)
                self._imported_ids.update(fixed)
                self._dirty = True
                # Set to False disables unnecessary update-findings()
                log.info(
                    "marked %i unmodified findings for archival: %s",
                    len(fixed),
                    json.dumps(fixed),
                )

    def _flush_cache(self, just_one=None, batch_size=100):
        """Import all cached findings to SecurityHub"""

        # If no updates have been made, this is a no-op
        if just_one is None and not self._dirty:
            log.info("No dirty findings to import")
            return

        # We need a list of findings
        if just_one is not None:
            todo = [just_one]
        else:
            todo = [self._cache[x] for x in self._imported_ids]

        # Do the import (in pieces, as necessary)
        while todo:
            if len(todo) > batch_size:
                donow = todo[:batch_size]
                todo = todo[batch_size:]
            else:
                donow = todo
                todo = []
            try:
                log.info("Importing %i findings to SecurityHub", len(donow))
                log.debug("Request: Findings=%s", json.dumps(donow))
                response = self._securityhub.batch_import_findings(Findings=donow)
                if response["FailedFindings"]:
                    log.error("Import response (failure): %s", json.dumps(response))
                else:
                    log.debug("Import response (success): %s", json.dumps(response))
            except Exception:  # pylint: disable=broad-except
                log.exception("SecurityHub exception:")

        if just_one is None:
            self._dirty = False

    def new_session(self, **kwargs):
        """Create new session and start SecurityHub import monitor"""

        self._imported_ids = set()  # Finding IDs imported in transaction
        self._account = None  # AWS account

        # Create new session with caller-supplied arguments
        self._session = boto3.session.Session(**kwargs)

        # Create SecurityHub object derived from this session
        self._securityhub = self._session.client(
            "securityhub", region_name=SECURITY_HUB_REGION
        )

    def aws_account(self):
        """Returns the AWS account for the specified session"""

        if self._account is None:
            try:
                self._account = self._session.client("sts").get_caller_identity()[
                    "Account"
                ]
            except Exception:  # pylint: disable=broad-except
                log.exception("Unable to retrieve AWS account information")
                self._account = "UNKNOWN"

        return self._account

    def aws_region(self):
        """Returns the AWS region for the specified session"""

        try:
            return self._session.region_name
        except Exception:  # pylint: disable=broad-except
            log.exception("Unable to retrieve AWS account information")
            return "UNKNOWN"

    def list_all_findings(self):
        """Return list of cached finding identifiers"""

        return list(self._cache.keys())

    def list_modified_findings(self):
        """Return list of modified finding identifiers"""

        return list(self._imported_ids)

    def list_unmodified_findings(self):
        """Return list of unmodified finding identifiers"""

        stale_ids = set(self._cache.keys()) - self._imported_ids
        return list(stale_ids)

    def get_finding_severities(self):
        """Return dictionary of severity distributions"""

        return self._demographics["severity"]

    def get_finding_data(self):
        """Return dictionary of extended finding information"""

        return self._demographics

    def begin_transaction(self, scope_prefix, scope_region=None):
        """Start a new batch of SecurityHub updates"""

        if self._in_transaction:
            raise RuntimeError("begin_transaction() called while in transaction")
        self._prefix = scope_prefix
        self._region = scope_region
        self._imported_ids = set()
        self._load_cache()
        self._demographics = {
            "severity": {},
            "kind": {"created": 0, "updated": 0, "archived": 0},
        }
        self._began_transaction = datetime.datetime.utcnow().strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        self._in_transaction = True

    def end_transaction(self, autoarchive=False, dont_archive=None):
        """End a batch of SecurityHub updates"""

        if self._in_transaction:
            # Compile "demographic" data about findings in transaction
            for finding_id in self._imported_ids:
                sev = self._cache[finding_id]["Severity"]["Normalized"]
                if sev in self._demographics["severity"]:
                    self._demographics["severity"][sev] += 1
                else:
                    self._demographics["severity"][sev] = 1
                kind = (
                    "updated"
                    if self._cache[finding_id]["CreatedAt"] < self._began_transaction
                    else "created"
                )
                self._demographics["kind"][kind] += 1

            # If requested, archive old findings. This is where
            # self._demographics["kind"]["archived"] is computed.
            if autoarchive:
                self._mark_unmodified_findings(dont_archive)

            # Make demo values strings to sidestep serialization issues
            for key in self._demographics:
                for item in self._demographics[key]:
                    self._demographics[key][item] = str(self._demographics[key][item])

            # Send all changes to SecurityHub
            self._flush_cache()
            self._in_transaction = False
        else:
            raise RuntimeError("end_transaction() called while not in transaction")

    def get_finding(self, finding_id):
        """Return finding from cache"""

        if finding_id in self._cache:
            log.debug("Found %s in cache", finding_id)
            return copy.deepcopy(self._cache[finding_id])
        if self._in_transaction and finding_id.startswith(self._prefix):
            log.debug("No %s in cache", finding_id)
            return None
        log.debug("No %s in cache, trying single load", finding_id)
        return self._load_one(finding_id)

    def put_finding(self, f):
        """Create/overwrite finding in cache"""

        finding_id = f["Id"]
        self._cache[finding_id] = f

        # If we are in a transaction, this is a writeback operation
        # If we are not in a transaction, make this writethrough
        if self._in_transaction:
            self._dirty = True
            self._imported_ids.add(finding_id)
            if not finding_id.startswith(self._prefix):
                log.warning(
                    "id %s does not match transaction prefix %s",
                    finding_id,
                    self._prefix,
                )
            if self._region is not None:
                for i in f["Resources"]:
                    if i["Region"] != self._region:
                        log.warning(
                            "id %s resource region %s does not match transaction region %s",
                            finding_id,
                            i["Region"],
                            self._region,
                        )
        else:
            self._flush_cache(just_one=f)

    def mark_active_finding(self, finding_id):
        """Consider the specified finding active"""

        self._imported_ids.add(finding_id)
