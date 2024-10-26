# security_app/aws_utils.py

import boto3
from aws_security_dashboard.settings import AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

def get_aws_client(service_name):
    """Utility function to initialize AWS clients."""
    return boto3.client(
        service_name,
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )
