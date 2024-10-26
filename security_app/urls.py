# security_app/urls.py
from django.urls import path
from django.contrib.auth import views as auth_views  # Import auth_views for authentication views
from . import views

urlpatterns = [
    path('login/', views.CustomLoginView.as_view(), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),  # Logout view
    path('iam-users/', views.iam_users_list, name='iam_users'),
    path('guardduty-findings/', views.guardduty_findings, name='guardduty_findings'),
    path('kms-keys/', views.kms_keys_list, name='kms_keys'),
    path('cloudtrail-logs/', views.cloudtrail_logs, name='cloudtrail_logs'),
]