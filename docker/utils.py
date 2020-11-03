import logging
import common.securityhub
from .aws_clients import ECRClient
import wrapper


def initialize_logging():
    # Adjust log format if running on a terminal
    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s"
    )

    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.INFO)
    logging.getLogger("urllib3").setLevel(logging.CRITICAL)


def get_vpc_id():
    parameters = wrapper.get_parameters()
    # store script parameter in parameter table?
    # sh_parameters = parameters.get("sh_params")
    return parameters["vpc_id"]
