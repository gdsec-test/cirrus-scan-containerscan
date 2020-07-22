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


def set_severity(normalized, original=None):
    """Generate a complete ASFF Severity object"""

    # From AWS SecurityHub User Guide on 7/15/2019:
    #
    # Severity Label   Severity Score Range
    # Informational                0
    # Low                       1–39
    # Medium                   40–69
    # High                     70–89
    # Critical                90–100

    if normalized < 0 or normalized > 100:
        raise ValueError("Severity must be in range 0-100")
    if normalized == 0:
        label = "INFORMATIONAL"
    elif normalized < 40:
        label = "LOW"
    elif normalized < 70:
        label = "MEDIUM"
    elif normalized < 90:
        label = "HIGH"
    else:
        label = "CRITICAL"

    sev_dict = {"Normalized": normalized, "Label": label}
    if original is not None:
        sev_dict["Original"] = str(original)

    return sev_dict


class Finding:  # pylint: disable=too-many-instance-attributes
    """Encapsulated SecurityHub Finding"""

    # These fields can be updated by BatchImportFindings, but not
    # by BatchUpdateFindings.
    IMPORT_FIELDS = {
        "AwsAccountId",
        "Compliance",
        "CreatedAt",
        "Description",
        "FirstObservedAt",
        "GeneratorId",
        "Id",
        "LastObservedAt",
        "Malware",
        "Network",
        "Process",
        "ProductArn",
        "ProductFields",
        "RecordState",
        "Remediation",
        "Resources",
        "SchemaVersion",
        "SourceUrl",
        "ThreatIntelIndicators",
        "Title",
        "UpdatedAt",
    }

    # These fields must be present in order for a finding to be valid (importable).
    MANDATORY_FIELDS = {
        "AwsAccountId",
        "CreatedAt",
        "Description",
        "GeneratorId",
        "Id",
        "ProductArn",
        "Resources",
        "SchemaVersion",
        "Severity",
        "Title",
        "Types",
        "UpdatedAt",
    }

    # These fields can be updated by BatchUpdateFindings, but not
    # BatchImportFindings (unless the finding is new)
    UPDATE_FIELDS = {
        "Confidence",
        "Criticality",
        "Note",
        "RelatedFindings",
        "Severity",
        "Types",
        "UserDefinedFields",
        "VerificationState",
        "Workflow",
    }

    # Collectively, these define the fields that are valid for a finding
    ALLOWED_FIELDS = IMPORT_FIELDS | UPDATE_FIELDS

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
        self._needbut = set()
        self._needbit = set()

        # Attempt to load an existing Security Hub finding if finding_id given
        if finding_id:
            result = self._manager.get_finding(finding_id)

            if result:
                self._finding = result
                self._isnew = False
            else:
                self._finding["Id"] = finding_id
                self._needbit.add("Id")

        # Populate attributes from a supplied dictionary if given. This set
        # overrides any existing attributes, except we attempt to cleverly
        # merge dict and list attributes when merge is True.
        for key in override_dict if override_dict is not None else {}:
            changed = False

            if key in Finding.ALLOWED_FIELDS:
                if merge and key in self._finding:
                    # Potentially merge multi-valued content
                    if isinstance(self._finding[key], dict):
                        # Dictionary: add/replace user-specified members
                        self._finding[key].update(override_dict[key])
                        changed = True  # inexact but conservative
                    elif isinstance(self._finding[key], list):
                        # List: add members that are not already present
                        # and preserve order
                        not_present = [
                            member
                            for member in override_dict[key]
                            if member not in self._finding[key]
                        ]
                        if not_present:
                            self._finding[key].extend(not_present)
                            changed = True
                    elif self._finding[key] != override_dict[key]:
                        # Simple attributes can't be merged; overwrite
                        self._finding[key] = override_dict[key]
                        changed = True
                elif (
                    key not in self._finding or self._finding[key] != override_dict[key]
                ):
                    # Set content absolutely (replacing any prior data)
                    self._finding[key] = override_dict[key]
                    changed = True

                if changed:
                    # Record the change only if something actually changed
                    self._setbyuser.add(key)
                    # How do we need to send this change?
                    if not self._isnew and key in Finding.UPDATE_FIELDS:
                        self._needbut.add(key)
                    else:
                        self._needbit.add(key)

        # Similarly, we can define default attributes (which are set
        # only if they are missing)
        for key in default_dict if default_dict is not None else {}:
            if key in Finding.ALLOWED_FIELDS and key not in self._finding:
                self._finding[key] = default_dict[key]
                # How do we need to send this change?
                if not self._isnew and key in Finding.UPDATE_FIELDS:
                    self._needbut.add(key)
                else:
                    self._needbit.add(key)

        # If "RelatedFindings" is an empty list, remove it because the import
        # will fail with an empty list?!
        if (
            "RelatedFindings" in self._finding
            and self._finding["RelatedFindings"] == []
        ):
            del self._finding["RelatedFindings"]

        # Populate required fields if they're not present. Existing findings
        # by definition have all required fields, so we can skip this step.
        if self._isnew:
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
                "Severity": set_severity(0),
                "Types": ["Software and Configuration Checks/GoDaddy Cirrus Scan"],
                "ProductArn": "arn:aws:securityhub:%s:%s:product/%s/default"
                % (
                    SECURITY_HUB_REGION,
                    self._manager.aws_account(),
                    self._manager.aws_account(),
                ),
                "ProductFields": {
                    "CompanyName": "GoDaddy",
                    "ProductName": "Cirrus Scan",
                },
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
                    self._needbit.add(key)
                elif isinstance(value, dict) and isinstance(self._finding[key], dict):
                    # Define (only) missing elements in existing dictionaries
                    for subkey in value:
                        if subkey not in self._finding[key]:
                            self._finding[key][subkey] = value[subkey]
                            self._needbit.add(key)
                # To reflect on... Should lists have special treatment also,
                # and if so, what is the proper behavior?

    def __getattr__(self, k):
        return self._finding.get(k, None)

    def __setattr__(self, k, v):
        if k == "Id" and k in self._finding and v != self._finding[k]:
            raise ValueError("identifier is read-only")
        if k in Finding.ALLOWED_FIELDS:
            if k not in self._finding or self._finding[k] != v:
                self._finding[k] = v
                self._setbyuser.add(k)
                # How do we need to send this change?
                if not self._isnew and k in Finding.UPDATE_FIELDS:
                    self._needbut.add(k)
                else:
                    self._needbit.add(k)
        else:
            super().__setattr__(k, v)

    def to_dict(self):
        """Return a dict of the finding's attributes"""

        return self._finding

    def list_imports(self):
        """Return a set of attribute changes for BatchImportFindings"""

        return self._needbit

    def list_updates(self):
        """Return a set of attributes changes for BatchUpdateFindings"""

        return self._needbut

    def is_new(self):
        """Report whether this finding is new or existed previously"""

        return self._isnew

    def _validate_attributes(self):
        """Ensure attributes are consistent"""

        # Some attributes must exist for a finding to be valid
        missing = self.MANDATORY_FIELDS.difference(set(self._finding.keys()))
        if missing:
            log.error("Required attributes are missing: %s", missing)
            return False

        # Some attributes are not mandatory for Security Hub, but are mandatory
        # for us so that findings can be categorized correctly.
        if "ProductFields" not in self._finding:
            self._finding["ProductFields"] = {}
        for key, value in {
            "CompanyName": "GoDaddy",
            "ProductName": "Cirrus Scan",
        }.items():
            if key not in self._finding["ProductFields"]:
                self._finding["ProductFields"][key] = value

        # Some attributes are generated by Security Hub and should not
        # be modified by us. If present, remove them to ensure Security Hub
        # has full latitude to adjust them (hopefully to be consistent with
        # other, user-supplied, fields!)
        for key in [
            x for x in self._finding.get("ProductFields", {}) if x.startswith("aws/")
        ]:
            del self._finding["ProductFields"][key]

        return True

    def _update_state(self):
        """Maintain timestamp attributes"""

        # Modify fields for update scenario
        utcnow = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        self._finding["UpdatedAt"] = utcnow
        self._needbit.add("UpdatedAt")
        if "CreatedAt" not in self._finding:
            self._finding["CreatedAt"] = utcnow
            self._needbit.add("CreatedAt")
        if "LastObservedAt" in self._finding and "FirstObservedAt" not in self._finding:
            self._finding["FirstObservedAt"] = self._finding["LastObservedAt"]
            self._needbit.add("FirstObservedAt")

    def _import_finding(self):
        """Import Security Hub finding"""

        log.debug("Importing Security Hub finding: %s", json.dumps(self._finding))
        self._manager.put_finding(self._finding, self._needbit, self._needbut)

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
            self._isnew = True
            self._needbut = {}
            return

        # Merge. Precedence (from highest to lowest) is:
        # 1. User changes (keys in self._setbyuser, data in self._finding)
        # 2. Old data in named finding (in new_baseline)
        # 3. Old data (probably inherited defaults) (in self._finding)
        for k in new_baseline:
            # For every attribute of the target finding
            if k not in self._setbyuser:
                # Attribute not set by user, inherit it
                self._finding[k] = new_baseline[k]

        # Retroactively check for attribute changes as if we were doing
        # them all over again.
        for k in self._finding:
            if k not in new_baseline or new_baseline[k] != self._finding[k]:
                # This attribute effectively is being updated
                self._setbyuser.add(k)
                # How does it need to be sent to Security Hub?
                if k in Finding.UPDATE_FIELDS:
                    self._needbut.add(k)
                else:
                    self._needbit.add(k)

        self._finding["Id"] = new_finding_id
        self._setbyuser.add("Id")
        self._needbit.add("Id")
        self._isnew = False

    def save(self):
        """Update Security Hub finding by reimporting it"""

        self._update_state()
        if self._validate_attributes():
            self._import_finding()
            return True
        return False


class SecurityHub_Manager:  # pylint: disable=too-many-instance-attributes,invalid-name
    """Wrapper for AWS Session() and extended SecurityHub semantics"""

    def __init__(
        self, scope_prefix=None, scope_region=None, scope_account="self", **kwargs
    ):
        self._session = None  # AWS Session object
        self._securityhub = None  # AWS SecurityHub object
        self._master = False  # Is this SecurityHub master account?
        self._prefix = scope_prefix  # User-supplied finding ID prefix
        self._region = scope_region  # User-supplied target region
        self._account_filter = None  # User-supplied target account(s)
        self._cache = {}  # In-mem finding cache
        self._in_transaction = False  # Are we buffering updates?
        self._dirty = False  # No changes made (yet)
        self._imported_ids = {}  # of set()  # Finding IDs imported in transaction
        self._account = None  # AWS account
        self._demographics = None  # End-of-transaction finding summary
        self._began_transaction = None  # When did transaction begin?

        self.new_session(**kwargs)  # Set up all context

        # Construct account filter, as appropriate
        # We understand "self", "all", and a list of explicit accounts
        if scope_account == "all":
            # All visible accounts - no filtering
            self._account_filter = None
        elif isinstance(scope_account, list):
            # Only the supplied list of accounts
            self._account_filter = [
                {"Comparison": "EQUALS", "Value": x} for x in scope_account
            ]
        else:  # elif scope_account == "self":
            # Only findings for our own account
            self._account_filter = [{"Comparison": "EQUALS", "Value": self._account}]

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

        self._cache = {}  # keys: account, id; value: finding
        processed = 0

        aws_filters = {
            "Id": [{"Comparison": "PREFIX", "Value": self._prefix}],
            "RecordState": [{"Comparison": "EQUALS", "Value": "ACTIVE"}],
        }
        if self._region is not None:
            aws_filters["ResourceRegion"] = [
                {"Comparison": "EQUALS", "Value": self._region}
            ]
        if self._account_filter is not None:
            aws_filters["AwsAccountId"] = self._account_filter

        result = self._securityhub.get_findings(
            MaxResults=batch_size, Filters=aws_filters
        )
        while result:
            for f in result["Findings"]:
                if f["AwsAccountId"] not in self._cache:
                    self._cache[f["AwsAccountId"]] = {}
                self._cache[f["AwsAccountId"]][f["Id"]] = f
                processed += 1
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
        log.info(
            "cached %i findings for prefix %s", processed, self._prefix,
        )

    def _load_one(self, finding_id, account_id=None):
        """Attempt to load one finding into cache"""

        acct = self._account if account_id is None else account_id

        aws_filters = {
            "Id": [{"Value": finding_id, "Comparison": "EQUALS"}],
            "AwsAccountId": [{"Comparison": "EQUALS", "Value": acct}],
            "RecordState": [{"Comparison": "EQUALS", "Value": "ACTIVE"}],
        }

        result = self._securityhub.get_findings(Filters=aws_filters)["Findings"]

        if result:
            finding = result[0]
            if finding["AwsAccountId"] not in self._cache:
                self._cache[finding["AwsAccountId"]] = {}
            self._cache[finding["AwsAccountId"]][finding_id] = finding
            return finding
        return None

    def _mark_unmodified_findings(self, dont_archive=None):
        """Mark unmodified findings as archived"""

        utcnow = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # If we need regex construction, do it once for everything
        if dont_archive is not None:
            # Construct a single regex equivalent to the input list
            full_pattern = ""
            for user_regex in dont_archive:
                full_pattern += "|" + user_regex
            full_regex = re.compile(full_pattern[1:])

        for acct in self._cache:
            if acct not in self._imported_ids:
                self._imported_ids[acct] = set()

            # We should modify all cached findings that have not been updated
            # by the caller during this transaction, which are not already
            # archived.
            stale_ids = set(self._cache[acct].keys()) - self._imported_ids[acct]

            # dont_archive is a list of regular expressions that specify findings
            # we do not want to autoarchive under any circumstances. All matching
            # findings in the stale set should be removed from it.
            if stale_ids and dont_archive is not None:

                # Test every member of stale_ids and note all matches
                ignored_ids = set()
                for finding_id in stale_ids:
                    if full_regex.search(finding_id) is not None:
                        ignored_ids.add(finding_id)

                # If findings should be retained, remove them from stale set
                if ignored_ids:
                    stale_ids.difference_update(ignored_ids)
                    log.info(
                        "retaining %i unmodified findings for %s: %s",
                        len(ignored_ids),
                        acct,
                        json.dumps(list(ignored_ids)),
                    )
                else:
                    log.info(
                        "no unmodified findings for %s matched exclusion filters.", acct
                    )

            # If we still have findings to autoarchive, update each of them
            if stale_ids:
                fixed = []
                for finding_id in stale_ids:
                    if self._cache[acct][finding_id]["RecordState"] == "ACTIVE":
                        self._cache[acct][finding_id]["RecordState"] = "ARCHIVED"
                        self._cache[acct][finding_id]["Compliance"] = {
                            "Status": "PASSED"
                        }
                        # If UpdatedAt isn't revised, other changes are ignored
                        self._cache[acct][finding_id]["UpdatedAt"] = utcnow
                        fixed.append(finding_id)
                if fixed:
                    self._demographics["kind"]["archived"] += len(fixed)
                    self._imported_ids[acct].update(fixed)
                    self._dirty = True
                    # Set to False disables unnecessary update-findings()
                    log.info(
                        "marked %i unmodified findings in %s for archival: %s",
                        len(fixed),
                        acct,
                        json.dumps(fixed),
                    )

    def _flush_cache(self, just_one=None, batch_size=100):
        """Import all cached findings to SecurityHub"""

        # If no updates have been made, this is a no-op
        if just_one is None and not self._dirty:
            log.info("No dirty findings to import")
            return

        # We need a list of findings for the current account
        if just_one is not None:
            if just_one["AwsAccountId"] == self._account:
                todo = [just_one]
            else:
                log.error(
                    "Cannot import finding for account: %s", just_one["AwsAccountId"]
                )
                return
        else:
            # Scream loudly if there is an attempt to import findings for other
            # accounts; Security Hub does not permit this!
            all_accts = set(self._imported_ids.keys())
            if all_accts != set([self._account]):
                all_accts.discard(self._account)
                log.error("Cannot import findings for accounts: %s", all_accts)
            if self._account not in self._imported_ids:
                # There is nothing to do for this account
                return
            todo = [
                self._cache[self._account][x] for x in self._imported_ids[self._account]
            ]

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

                    # Recover gracefully from this error, which commonly is due
                    # to validation errors within a single finding in the batch.
                    # Begin by collecting the set of failed identifiers.
                    dud_fids = {f["Id"] for f in response["FailedFindings"]}

                    # We need humans to fix the errors, so all we can do here is
                    # count the bad findings so somebody knows there is a problem.
                    log.error("Discarding %i requested imports", len(dud_fids))
                    self._demographics["kind"]["failed"] += len(dud_fids)

                    # Return any non-bad findings in the current batch to the
                    # todo list, so we'll try again to send them to Security Hub.
                    todo.extend([f for f in donow if f["Id"] not in dud_fids])
                else:
                    log.debug("Import response (success): %s", json.dumps(response))
            except Exception:  # pylint: disable=broad-except
                log.exception("SecurityHub exception:")

        if just_one is None:
            self._dirty = False

    def new_session(self, **kwargs):
        """Create new session and start SecurityHub import monitor"""

        self._imported_ids = {}  # of set()  # Finding IDs imported in transaction

        # Create new session with caller-supplied arguments
        self._session = boto3.session.Session(**kwargs)

        # Identify our AWS account
        self._account = None
        self.aws_account()

        # Create SecurityHub object derived from this session
        self._securityhub = self._session.client(
            "securityhub", region_name=SECURITY_HUB_REGION
        )

        # Determine if we are a SecurityHub master account. If we have a
        # subscription agreement, then we're a member account; if there is
        # no agreement, then we must be a master.
        try:
            result = self._securityhub.get_master_account()
            self._master = result["Master"]["MemberStatus"] != "Associated"
        except:
            self._master = True

    def is_master(self):
        """Is this a SecurityHub master account?"""

        return self._master

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

    def list_all_accounts(self):
        """Return list of accounts with findings"""

        return list(self._cache.keys())

    def list_all_findings(self, account_id=None):
        """Return list of cached finding identifiers"""

        if account_id is None:
            # This list may have duplicate instances of finding ids
            result = []
            for acct in self._cache:
                result.extend(self.list_all_findings(acct))
            return result
        elif account_id not in self._cache:
            return []
        return list(self._cache[account_id].keys())

    def list_modified_findings(self, account_id=None):
        """Return list of modified finding identifiers"""

        if account_id is None:
            # This list may have duplicate instances of finding ids
            result = []
            for acct in self._imported_ids:
                result.extend(self.list_modified_findings(acct))
            return result
        elif account_id not in self._imported_ids:
            return []
        return list(self._imported_ids[account_id])

    def list_unmodified_findings(self, account_id=None):
        """Return list of unmodified finding identifiers"""

        if account_id is None:
            # This list may have duplicate instances of finding ids
            result = []
            for acct in self._cache:
                result.extend(self.list_unmodified_findings(acct))
            return result
        elif account_id not in self._cache:
            # Bogus account can't have any findings (unmodified or otherwise)
            return []
        elif account_id not in self._imported_ids:
            # If no modified findings, then all of them are unmodified
            return list(self._cache[account_id].keys())
        # Otherwise, known findings not modified are unmodified
        return list(
            set(self._cache[account_id].keys()) - self._imported_ids[account_id]
        )

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
        self._imported_ids = {}  # of set()
        self._load_cache()
        self._demographics = {
            "severity": {},
            "kind": {"created": 0, "updated": 0, "archived": 0, "failed": 0},
        }
        self._began_transaction = datetime.datetime.utcnow().strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        self._in_transaction = True

    def end_transaction(self, autoarchive=False, dont_archive=None):
        """End a batch of SecurityHub updates"""

        if self._in_transaction:
            # Compile "demographic" data about findings in transaction
            for acct in self._imported_ids:
                for finding_id in self._imported_ids[acct]:
                    sev = self._cache[acct][finding_id]["Severity"]["Normalized"]
                    if sev in self._demographics["severity"]:
                        self._demographics["severity"][sev] += 1
                    else:
                        self._demographics["severity"][sev] = 1
                    kind = (
                        "updated"
                        if self._cache[acct][finding_id]["CreatedAt"]
                        < self._began_transaction
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

    def get_finding(self, finding_id, account_id=None):
        """Return finding from cache"""

        acct = self._account if account_id is None else account_id

        if acct in self._cache and finding_id in self._cache[acct]:
            log.debug("Found %s in cache", finding_id)
            return copy.deepcopy(self._cache[acct][finding_id])
        if self._in_transaction and finding_id.startswith(self._prefix):
            log.debug("No %s in cache", finding_id)
            return None
        log.debug("No %s in cache, trying single load", finding_id)
        return self._load_one(finding_id, acct)

    def put_finding(self, f, import_set, update_set):
        """Create/overwrite finding in cache"""

        finding_id = f["Id"]
        finding_acct = f["AwsAccountId"]

        # The f argument is a dict of finding attributes. The *_set arguments
        # are sets of attribute names that must be updated with
        # BatchImportFindings or BatchUpdateFindings, respectively.
        #
        # Assertion 1: If both sets are non-empty, it is always safe to do the
        # update before the import. Proof by contradiction: update requires the
        # finding to exist; if it does not exist, the finding must be new. But
        # if the finding is new, import is allowed to set (vs modify) all
        # attributes, and update_set will be empty. This contradicts our initial
        # assertion that update_set is non-empty. QED. If you are wondering why
        # we care, historically we did some fixups of "import" fields based on
        # chanes to "update" fields; using the opposite order would cause our
        # fixup to be undone by import before update could change the primary
        # field. Therefore, the place to do the update is here.
        #
        # Assertion 2: Generally, no useful updates can be performed. The _load_*
        # methods above restrict retrieved findings to the current account. The
        # BatchUpdateFindings call requires the current account to be the master
        # account. Findings of interest probably belong to the member accounts,
        # which can't update them. The point of this assertion is to justify
        # whining and doing nothing in the event an update actually is requested.

        if update_set:
            log.error(
                "Attribute updates to %s will be ignored: %s", finding_id, update_set
            )

        # Theoretically, import_set could be empty and we could skip any
        # remaining work. In practice, the act of calling .save() modifies
        # UpdatedAt before calling here, so import_set will never be empty. It
        # is conceivable that a scanner might generate an otherwise-unchanged
        # finding, and we would not want to discard that update... So the safest
        # course is to just save the finding and push it through to Security
        # Hub, even if we suspect the exercise might be pointless.

        # Update the finding cache, and then decide what to do about it.
        if finding_acct not in self._cache:
            self._cache[finding_acct] = {}
        self._cache[finding_acct][finding_id] = f

        # If we are in a transaction, this is a writeback operation
        # If we are not in a transaction, make this writethrough
        if self._in_transaction:
            self._dirty = True
            if finding_acct not in self._imported_ids:
                self._imported_ids[finding_acct] = set()
            self._imported_ids[finding_acct].add(finding_id)
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

    def mark_active_finding(self, finding_id, account_id=None):
        """Consider the specified finding active"""

        effective_acct = self._account if account_id is None else account_id
        if effective_acct not in self._imported_ids:
            self._imported_ids[effective_acct] = set()
        self._imported_ids[effective_acct].add(finding_id)
