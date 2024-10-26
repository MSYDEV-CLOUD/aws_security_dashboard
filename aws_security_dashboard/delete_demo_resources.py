# delete_demo_resources.py

import boto3
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
kms_client = boto3.client('kms', region_name=AWS_REGION,
                          aws_access_key_id=AWS_ACCESS_KEY_ID,
                          aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

# IAM Deletion
def delete_iam_user(username):
    """Deletes an IAM user created for the demo."""
    try:
        iam_client.delete_user(UserName=username)
        print(f"Deleted IAM user: {username}")
    except iam_client.exceptions.NoSuchEntityException:
        print(f"IAM user {username} does not exist.")

# KMS Key Deletion
def delete_kms_key(key_id):
    """Schedules the deletion of a KMS key."""
    try:
        kms_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
        print(f"Scheduled deletion for KMS Key: {key_id}")
    except kms_client.exceptions.NotFoundException:
        print(f"KMS key {key_id} does not exist.")

# Main execution
if __name__ == "__main__":
    print("Starting demo resource deletion...")

    # IAM user deletion
    delete_iam_user('demo-user')

    # Delete specific KMS Key (replace with actual key ID)
    demo_key_id = 'replace-with-demo-key-id'
    delete_kms_key(demo_key_id)

    print("Demo resource deletion completed.")
