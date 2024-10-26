# create_demo_resources.py

import boto3
import time
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# AWS credentials and configuration
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_REGION = os.getenv('AWS_REGION')

# AWS Clients
iam_client = boto3.client('iam', region_name=AWS_REGION,
                          aws_access_key_id=AWS_ACCESS_KEY_ID,
                          aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
gd_client = boto3.client('guardduty', region_name=AWS_REGION,
                         aws_access_key_id=AWS_ACCESS_KEY_ID,
                         aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
kms_client = boto3.client('kms', region_name=AWS_REGION,
                          aws_access_key_id=AWS_ACCESS_KEY_ID,
                          aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

# 1. IAM Actions
def create_iam_user(username):
    """Creates an IAM user for demo purposes."""
    try:
        response = iam_client.create_user(UserName=username)
        print(f"Created IAM user: {username}")
        return response
    except iam_client.exceptions.EntityAlreadyExistsException:
        print(f"IAM user {username} already exists.")

# 2. GuardDuty Actions
def check_guardduty_findings():
    """Checks for GuardDuty findings."""
    detectors = gd_client.list_detectors()['DetectorIds']
    if not detectors:
        print("No GuardDuty detectors found. Enable GuardDuty in the AWS Console.")
        return
    detector_id = detectors[0]
    print(f"Using GuardDuty detector: {detector_id}")

    findings = gd_client.list_findings(DetectorId=detector_id)['FindingIds']
    print(f"Found {len(findings)} findings." if findings else "No findings available.")

# 3. KMS Actions
def create_kms_key():
    """Creates a KMS key for demo purposes."""
    try:
        response = kms_client.create_key(Description='Demo KMS Key')
        key_id = response['KeyMetadata']['KeyId']
        print(f"Created KMS Key: {key_id}")
        return key_id
    except Exception as e:
        print(f"Error creating KMS key: {e}")

# 4. CloudTrail Activity Generation
def generate_cloudtrail_activity():
    """Generates CloudTrail events by creating an IAM user."""
    create_iam_user('demo-user')
    time.sleep(2)

# Main execution
if __name__ == "__main__":
    print("Starting demo resource creation...")

    # IAM user creation
    create_iam_user('demo-user')
    time.sleep(1)

    # Check GuardDuty findings
    check_guardduty_findings()

    # KMS key creation
    create_kms_key()

    # Generate CloudTrail activity
    generate_cloudtrail_activity()

    print("Demo resource creation completed.")
