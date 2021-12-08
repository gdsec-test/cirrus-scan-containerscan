import json
import csv
import requests
import os
import wrapper
from io import StringIO
from time import sleep
from datetime import datetime
from urllib3 import Retry
from common import securityhub
from errors import (
    ExitContainerScanner,
    RegistrationError,
    ProvisioningTimeoutError,
    DeprovisioningScannerTimeoutError,
)
from aws_clients import SSMClient, SecretsManagerClient, S3Client, ServiceCatalog


class PrismaClient:
    """Prisma client to fetch prisma token """

    SCAN_WAIT_TIME = 30
    REGISTERY_MAX_WAIT_TIME = 15
    PRISMA_COMPUTE_REST_API_URL = (
        "https://us-east1.cloud.twistlock.com/us-2-158254964/api/v1"
    )

    def __init__(self, logger, sts_client, sm_client, ec2_client):
        self.logger = logger
        self.sts_client = sts_client
        self.sm_client = sm_client
        self.ec2_client = ec2_client

    def get_token(self, iam_role_arn):
        """Retrieves Prisma Access key and secret key id from Secret Manager"""

        aws_creds = self.sts_client.assume_role(iam_role_arn)
        prisma_secrets = self.sm_client.get_prisma_secrets(aws_creds)

        payload = {
            "username": prisma_secrets["prismaAccessKeyId"],
            "password": prisma_secrets["prismaSecretKey"],
        }

        response = self.create_prisma_api_request(
            "POST", url="/authenticate", payload=payload
        )

        text_json = json.loads(response.text)
        token = text_json["token"]
        return token

    def register_ecr_registry(self, token, ecr_registry_name, scanner_dnsname):
        """Register ECR registry with Prisma"""

        if scanner_dnsname is None:
            raise RegistrationError

        params = {"hostname": scanner_dnsname}
        for setup_count in range(self.REGISTERY_MAX_WAIT_TIME):
            self.logger.debug(
                "waiting for defender to report to console, loop: %d" % setup_count
            )
            sleep(1 * 60)
            response = self.create_prisma_api_request(
                "GET", "/defenders/names", token=token, params=params
            )
            defenders = json.dumps(response.json())

            if scanner_dnsname in defenders:
                self.logger.info(
                    "Defender reported to console, ecr %s | scanner: %s"
                    % (ecr_registry_name, scanner_dnsname)
                )
                break

        # register ECR registry
        payload_template = '{"registry":"","repository":"","tag":"","cap":0,"os":"linux","hostname":"","namespace":"","useAWSRole":true,"version":"aws","credentialID":"","roleArn":"","scanners":1,"versionPattern":""}'
        payload = json.loads(payload_template)
        payload["registry"] = ecr_registry_name
        payload["hostname"] = scanner_dnsname.strip()

        self.create_prisma_api_request(
            "POST", "/settings/registry", token=token, payload=payload
        )

        self.logger.info(
            f"Registered {scanner_dnsname} with ECR registry {ecr_registry_name}!"
        )

    def force_ecr_registry_scan(self, token, ecr_registry_name):

        payload_template = '{ "tag" : { "registry" : "" } }'
        payload = json.loads(payload_template)
        payload["tag"]["registry"] = ecr_registry_name

        self.create_prisma_api_request(
            "POST", "/registry/scan", token=token, payload=payload
        )

        self.logger.info(f"Forced scan of ECR registry {ecr_registry_name}!")

    def retrieve_scanner_results(self, token, ecr_registry_name):

        param = "registry=" + ecr_registry_name

        # all results in csv format
        response = self.create_prisma_api_request(
            "GET", "/registry/download", token=token, params=param
        )

        self.logger.info(
            f"Retrieve scan results from ECR registry {ecr_registry_name}."
        )
        return response.text

    def wait_for_scan_completion(self):
        """Wait for the scan to be completed"""

        self.logger.info(
            "Waiting for {} minutes for Container Scan to finish".format(
                self.SCAN_WAIT_TIME
            )
        )
        # sleep for ?? minutes due to lack of progress api
        sleep(self.SCAN_WAIT_TIME * 60)

    def remove_defender(self, token, defender_name):
        self.logger.info("Removing defender: {}.".format(defender_name))
        self.create_prisma_api_request(
            "DELETE", "/defenders/" + defender_name, token=token
        )

    def create_prisma_api_request(
        self, method, url, token=None, payload=None, params=None
    ):
        """Helper function to make Prisma API requests"""
        headers = None
        response = None
        if payload is not None:
            payload = json.dumps(payload)

        # As we may hit Prisma API limits, try hitting Prisma at least 3 times before shutting down Container Scanner
        retries = Retry(
            total=3,
            status_forcelist={429, 501, 502, 503, 504},
            backoff_factor=1,
            respect_retry_after_header=True,
        )

        if token is not None:
            headers = {"Authorization": "Bearer " + token}
        else:
            headers = {"content-type": "application/json"}

        try:
            adapter = requests.adapters.HTTPAdapter(max_retries=retries)

            # initiate the session and then attach the Retry adaptor.
            session = requests.Session()
            session.mount("https://", adapter)

            session.headers = headers
            fullurl = self.PRISMA_COMPUTE_REST_API_URL + url

            if payload is not None and "username" not in payload:
                self.logger.debug(
                    "url: %s |method: %s  |payload : %s" % (url, method, payload)
                )
            if params is not None:
                self.logger.debug("params: %s" % params)

            if method == "POST":
                # self.logger.debug("calling post")
                response = session.post(
                    fullurl, params=params, data=payload, timeout=5.0
                )
            elif method == "DELETE":
                # self.logger.debug("calling delete")
                response = session.delete(
                    fullurl, params=params, data=payload, timeout=5.0
                )
            else:
                # self.logger.debug("calling get")
                response = session.get(
                    fullurl, params=params, data=payload, timeout=5.0
                )

            self.logger.debug(
                "Prisma API call status code {}".format(response.status_code)
            )
            if response.status_code == 200:
                return response
        except:
            self.logger.exception("Exception occurred in making Prisma request")
            raise ExitContainerScanner

        self.logger.error(
            f"Prisma API call from {url} method returning status code: {response.status_code}, {response.text}."
        )

        self.logger.error(f"Prisma API call failed from method: {url}. Exiting!")
        raise ExitContainerScanner


class Scanner:
    def __init__(self, logger, s3_client, sc_client, ssm_client, prisma_client):
        self.logger = logger
        self.s3_client = s3_client
        self.sc_client = sc_client
        self.ssm_client = ssm_client
        self.prisma_client = prisma_client

    def save_scanner_results(self, results):
        """Save scanner results to an S3 bucket."""
        self.logger.info("Saving Prisma scanner results")

        results_bucket = os.getenv("CIRRUS_SCAN_RESULTS_BUCKET")
        task_uuid = os.getenv("CIRRUS_SCAN_TASK_UUID", "UNDEFINED")
        results_key = "containerscan/%s/results.csv" % task_uuid

        temp_csv = "/tmp/results.csv"
        container_results_csv = open(temp_csv, "w")
        csv_writer = csv.writer(container_results_csv)

        with StringIO(results) as input_file:
            csv_reader = csv.reader(input_file, delimiter=",", quotechar='"')
            for row in csv_reader:
                csv_row = row
                csv_writer.writerow(csv_row)

        container_results_csv.close()

        self.s3_client.upload_file(temp_csv, results_bucket, results_key)

        if os.path.isfile(temp_csv):
            os.remove(temp_csv)

    def evaluate_scanner_results(self, handle, csv_results):
        """Evaluate scanner results and generate Security Hub findings.

        Two things will happen
        1. Convert CSV Result from Prisma to easily consumable format.

        ```
        prisma_results = {
            "<repository_name>" : {
                "<tag>": {
                    "somepackage:1.0.3": [row_resource, row_resource, row_resource, ...],
                    "hello-world:4.5": [row_resource, row_resource, row_resource, ...],
                    ...
                    "gd_prisma_compliance": [row_resource, row_resource, ...]
                },
                ...
            },
            ...
        }
        ```

        2. Create corresponding ASFF payload object and publish.
        """
        self.logger.info("Evaluating Prisma scanner results")

        prisma_results = {}  # Logical grouping of csv interpretation
        gd_compliance_type = "gd_prisma_compliance"
        aws_region = handle.aws_region()

        csv_results = csv.DictReader(csv_results.splitlines(), delimiter=",")

        for result in csv_results:
            severity = result.get("Severity", "NONE").capitalize()

            if severity == "None" or severity == "":
                self.logger.warn("Unexpected : Row with no Severity found - Skipping.")
                continue

            # Only process High/Critical finding
            if severity not in set({"High", "Critical"}):
                continue

            repository_name = result["Repository"]
            repository_id = result["Id"]
            tag = result["Tag"]

            if not prisma_results.get(repository_name):
                prisma_results[repository_name] = {}

            if not prisma_results[repository_name].get(tag):
                prisma_results[repository_name][tag] = {}

            container_map = prisma_results[repository_name][tag]

            row_resource = {
                "CVSS": result.get("CVSS"),
                "Description": result.get("Description"),
                "Id": repository_id,
                "Repository": repository_name,
                "Severity": severity,
                "Vulnerability ID": result.get("Vulnerability ID"),
                "Vulnerability Type": result.get("Type"),
            }

            if result.get("CVE ID"):
                row_resource["CVE ID"] = result.get("CVE ID")
                row_resource["Fix Status"] = result.get("Fix Status")
                row_resource["Package"] = result.get("Source Package") or result.get(
                    "Packages"
                )
                row_resource[
                    "Problem"
                ] = f"{row_resource['Package']}:{result.get('Package Version')}"
            else:
                row_resource["Package"] = gd_compliance_type
                row_resource["Problem"] = gd_compliance_type
                row_resource["Cause"] = result.get("Cause", "")

            if not container_map.get(row_resource["Problem"]):
                container_map[row_resource["Problem"]] = []

            container_map[row_resource["Problem"]].append(row_resource)

        self.logger.info("Finished reading csv file, generating findings...")

        for repository, tag_map in prisma_results.items():
            for tag, problem_map in tag_map.items():
                for problem, resources in problem_map.items():
                    repo_id = resources[0].get("Id")
                    severity = "High"
                    description_field = ""
                    recommendation_field = ""
                    vulnerabilities = []

                    if problem == gd_compliance_type:  # Prisma Compliance Type
                        description_field = (
                            f"{len(resources)} Compliance Vulnerabilities were found in the ECR image.\n\n"
                            + f"Image URI : {repo_id}\n"
                            + "Problem:\n"
                        )

                        recommendation_field = "Please revisit the ECR image, fix the idenfified compliance issues."

                        for r in resources:

                            if r["Severity"] == "Critical":
                                severity = r["Severity"]

                            compliance_row = f"    - {r['Description']}\n"

                            if description_field.endswith("- ...\n"):
                                continue  # Skip, but we still need to calculate severity

                            # Should be less than 1024 - 20 chars buffer
                            if len(description_field) + len(compliance_row) > 1004:
                                self.logger.warn(
                                    "Comliance Description will be larger than max char of 1024, adding ... instead."
                                )
                                description_field += "    - ...\n"
                            else:
                                description_field += compliance_row
                    else:  # CVE Type

                        description_field = (
                            f"{len(resources)} CVE Vulnerabilities were found in the ECR image.\n\n"
                            + f"Image URI : {repo_id}\n"
                            + f"Package: {problem}\n"
                            + "CVE (CVSS):\n"
                        )

                        for r in resources:

                            if r["Severity"] == "Critical":
                                severity = r["Severity"]

                            vulnerability = {
                                "Id": r["CVE ID"],
                                "ReferenceUrls": [
                                    f"https://nvd.nist.gov/vuln/detail/{r['CVE ID']}",
                                    f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={r['CVE ID']}",
                                ],
                            }

                            try:
                                vulnerability["Cvss"] = [
                                    {"BaseScore": float(r["CVSS"])}
                                ]
                            except:
                                self.logger.warning(
                                    f"Undefined CVSS [{r['CVSS']}] found for [{vulnerability['Id']}], skipping."
                                )

                            vulnerabilities.append(vulnerability)

                        self.logger.info("Sorting Vulnerabilities for the finding.")
                        vulnerabilities.sort(
                            key=lambda obj: obj["Cvss"][0]["BaseScore"]
                            if obj.get("Cvss")
                            else 0.0,
                            reverse=True,
                        )

                        for vuln in vulnerabilities:
                            cvss_score = (
                                vuln["Cvss"][0]["BaseScore"]
                                if vuln.get("Cvss")
                                else "N/A"
                            )
                            cve_row = f"    - { vuln['Id'] } ({ cvss_score })\n"

                            if description_field.endswith("- ...\n"):
                                break

                            # Should be less than 1024 - 20 chars buffer
                            if len(description_field) + len(cve_row) > 1004:
                                self.logger.warn(
                                    "CVE Description will be larger than max char of 1024, adding ... instead."
                                )
                                description_field += "    - ...\n"
                            else:
                                description_field += cve_row

                        recommendation_field = '**Please use "https://nvd.nist.gov/vuln/detail/{CVE-ID}" for more detail. ex) https://nvd.nist.gov/vuln/detail/CVE-2020-123456**'

                    asff_payload = {
                        "Id": f"containerscan/{aws_region}/{repository}/{tag}/{r['Package']}",
                        "Title": f"Container Scan [{aws_region}]: Vulnerability found with [{problem}] in [{repository}:{tag}]",
                        "Description": description_field,
                        "Remediation": {
                            "Recommendation": {"Text": recommendation_field}
                        },
                        "GeneratorId": "Container Scan",
                        "Resources": [
                            {
                                "Type": "Container",
                                "Id": f"arn:aws:ecr:{aws_region}:{repo_id.split('.')[0]}:repository/{r['Repository']}",
                                "Region": aws_region,
                                "Details": {
                                    "Container": {
                                        "ImageName": r["Repository"],
                                        "ImageId": repo_id,
                                    },
                                },
                            },
                        ],
                        # TODO : Comeback and modify severity normalization.
                        "Severity": securityhub.set_severity(
                            wrapper.get_parameters().get("severity", 1),
                            original=severity,
                        ),
                    }

                    if vulnerabilities:
                        asff_payload["Vulnerabilities"] = vulnerabilities

                    try:
                        finding = handle.Finding(
                            asff_payload["Id"], override_dict=asff_payload
                        )

                        finding.save()
                    except Exception:
                        self.logger.exception("Error while processing scanner result:")

    def generate_informational_finding(self, handle):
        """Generate an informational finding indicating test is complete"""

        self.logger.debug("Test complete")
        utcnow = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        aws_region = handle.aws_region()

        # Generate a Security Hub finding
        finding_id = f"containerscan/complete/{aws_region}"
        finding = handle.Finding(finding_id)

        finding.ProductFields["Environment"] = os.getenv(
            "CIRRUS_SCAN_ACCOUNT_ENVIRONMENT", "UNKNOWN"
        )
        finding.ProductFields["TaskUuid"] = os.getenv(
            "CIRRUS_SCAN_TASK_UUID", "UNKNOWN"
        )
        finding.ProductFields["TeamName"] = os.getenv(
            "CIRRUS_SCAN_ACCOUNT_TEAM_NAME", "UNKNOWN"
        )

        finding.Title = f"Container Scan [{aws_region}]: finished at {utcnow}"
        finding.Compliance = {"Status": "PASSED"}
        finding.Description = "No description available."
        finding.GeneratorId = "Container Scan"
        finding.LastObservedAt = utcnow

        try:
            finding.save()
        except Exception:
            self.logger.exception("Error while processing scanner completed result:")

    def remove(self, provisioned_product_name, task_name, prisma_token, defender_name):
        self.logger.info("Prisma Scanner Cleanup Started")
        if (
            provisioned_product_name is not None
            and self.sc_client.provisioned_product_exists(provisioned_product_name)
        ):
            self.sc_client.deprovision_scanner(provisioned_product_name)

        if task_name is not None and self.ssm_client.has_task_parameter(task_name):
            self.ssm_client.delete_task_parameter(task_name)

        if defender_name is not None:
            self.prisma_client.remove_defender(prisma_token, defender_name)

        self.logger.info("Prisma Scanner Cleanup Finished")
