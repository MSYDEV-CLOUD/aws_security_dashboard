# security_app/models.py
from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('analyst', 'Security Analyst'),
        ('readonly', 'Read-Only')
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='readonly')

    def __str__(self):
        return f"{self.user.username} ({self.role})"
