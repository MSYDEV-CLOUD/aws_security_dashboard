# security_app/views.py

from django.shortcuts import render
from django.http import HttpResponse
import boto3
from .decorators import role_required
from aws_security_dashboard.settings import AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
from django.contrib.auth.views import LoginView

# IAM Users List - Accessible only to admin users
@role_required('admin')
def iam_users_list(request):
    iam_client = boto3.client(
        'iam',
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )
    try:
        users = iam_client.list_users()['Users']
    except iam_client.exceptions.ClientError as e:
        # Return an error response if there's an issue accessing IAM
        return HttpResponse(f"Error accessing IAM: {e}", status=500)
    return render(request, 'security_app/iam_users.html', {'users': users})


# GuardDuty Findings - No role restriction for demo purposes
@role_required('analyst', 'admin')
def guardduty_findings(request):
    gd_client = boto3.client(
        'guardduty',
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )
    try:
        detectors = gd_client.list_detectors()['DetectorIds']
        
        # Check if detectors list is empty
        if not detectors:
            error_message = "No GuardDuty detectors found. Enable GuardDuty in the AWS Console to view findings."
            return render(request, 'security_app/error.html', {'error_message': error_message})

        detector_id = detectors[0]
        findings = gd_client.list_findings(DetectorId=detector_id)['Findings']
        
        # Check if findings are available
        if not findings:
            return render(request, 'security_app/guardduty_findings.html', {'findings': [], 'message': "No GuardDuty findings available."})

        # Fetch findings details if findings are present
        findings_details = gd_client.get_findings(DetectorId=detector_id, FindingIds=findings)['Findings']
        return render(request, 'security_app/guardduty_findings.html', {'findings': findings_details})
    
    except gd_client.exceptions.ClientError as e:
        return render(request, 'security_app/error.html', {'error_message': f"Error accessing GuardDuty: {e}"})

# KMS Keys List - Accessible only to admin users
@role_required('admin')
def kms_keys_list(request):
    kms_client = boto3.client(
        'kms',
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )
    try:
        keys = kms_client.list_keys()['Keys']
    except kms_client.exceptions.ClientError as e:
        # Return an error response if there's an issue accessing KMS
        return HttpResponse(f"Error accessing KMS: {e}", status=500)
    return render(request, 'security_app/kms_keys.html', {'keys': keys})


# CloudTrail Logs - Accessible to both admin and analyst roles
@role_required('analyst', 'admin')
def cloudtrail_logs(request):
    ct_client = boto3.client(
        'cloudtrail',
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )
    try:
        events = ct_client.lookup_events()['Events']
    except ct_client.exceptions.ClientError as e:
        # Return an error response if there's an issue accessing CloudTrail
        return HttpResponse(f"Error accessing CloudTrail: {e}", status=500)
    return render(request, 'security_app/cloudtrail_logs.html', {'events': events})


class CustomLoginView(LoginView):
    template_name = 'security_app/login.html'