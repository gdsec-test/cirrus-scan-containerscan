def deprovision_scanner(provisioned_product_name):
    """Deprovision a Tenable scanner, using CloudFront, Service Catalog, EC2, etc."""
    pass


def provision_scanner(vpc_id):
    """Provision a Prisma scanner, using Service Catalog product EC2"""
    pass


def load_in_script():
    pass


def generate_informational_finding(handle):
    """Generate an informational finding indicating test is complete"""
    pass


def get_finding_ids_of_stopped_instances(handle, do_not_archive):
    """Get regular expression for all stopped instances"""
    pass


def create_do_not_archive_expression(handle, ip_address):
    """Returns a regular expression to identify all the findings for a given IP address"""
    pass
