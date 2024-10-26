# security_app/views.py

from django.shortcuts import render
from django.http import HttpResponse
from .decorators import role_required
from .aws_utils import get_aws_client  # Import helper function
from django.contrib.auth.views import LoginView

# IAM Users List - Accessible only to admin users
@role_required('admin')
def iam_users_list(request):
    iam_client = get_aws_client('iam')
    try:
        users = iam_client.list_users()['Users']
    except iam_client.exceptions.ClientError as e:
        return render(request, 'security_app/error.html', {'error_message': f"Error accessing IAM: {e}"})
    return render(request, 'security_app/iam_users.html', {'users': users})

# GuardDuty Findings - Accessible to both analysts and admins
@role_required('analyst', 'admin')
def guardduty_findings(request):
    gd_client = get_aws_client('guardduty')
    try:
        detectors = gd_client.list_detectors()['DetectorIds']
        
        if not detectors:
            error_message = "No GuardDuty detectors found. Enable GuardDuty in the AWS Console to view findings."
            return render(request, 'security_app/error.html', {'error_message': error_message})

        detector_id = detectors[0]
        findings = gd_client.list_findings(DetectorId=detector_id)['Findings']

        if not findings:
            return render(request, 'security_app/guardduty_findings.html', {'findings': [], 'message': "No GuardDuty findings available."})

        findings_details = gd_client.get_findings(DetectorId=detector_id, FindingIds=findings)['Findings']
        return render(request, 'security_app/guardduty_findings.html', {'findings': findings_details})

    except gd_client.exceptions.ClientError as e:
        return render(request, 'security_app/error.html', {'error_message': f"Error accessing GuardDuty: {e}"})

# KMS Keys List - Accessible only to admin users
@role_required('admin')
def kms_keys_list(request):
    kms_client = get_aws_client('kms')
    try:
        keys = kms_client.list_keys()['Keys']
    except kms_client.exceptions.ClientError as e:
        return render(request, 'security_app/error.html', {'error_message': f"Error accessing KMS: {e}"})
    return render(request, 'security_app/kms_keys.html', {'keys': keys})

# CloudTrail Logs - Accessible to both admin and analyst roles
@role_required('analyst', 'admin')
def cloudtrail_logs(request):
    ct_client = get_aws_client('cloudtrail')
    try:
        events = ct_client.lookup_events()['Events']
    except ct_client.exceptions.ClientError as e:
        return render(request, 'security_app/error.html', {'error_message': f"Error accessing CloudTrail: {e}"})
    return render(request, 'security_app/cloudtrail_logs.html', {'events': events})

class CustomLoginView(LoginView):
    template_name = 'security_app/login.html'
