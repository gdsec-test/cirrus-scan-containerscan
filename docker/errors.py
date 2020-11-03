class ProvisioningTimeoutError(Exception):
    """Provision operation timed out"""

    pass


class RegistrationError(Exception):
    """ECR registry registration operation error"""

    pass


class ForceScanError(Exception):
    """Force scan operation error"""

    pass


class ScanningTimeoutError(Exception):
    """Scanning operation timed out"""

    pass


class DeprovisioningScannerTimeoutError(Exception):
    """VulnScanner Product not de-provisioned successfully"""

    pass


class SecretManagerRetrievalError(Exception):
    """Unable to retrieve Tenable API keys from Secret Manager"""

    pass


class ExitContainerScanner(Exception):
    """One of the resources required to run ContainerScanner is missing. Exiting!"""

    pass


class VPCNotFound(Exception):
    """Unable to locate VPC for scanner. Exiting!"""

    pass
