# security_app/decorators.py
from django.core.exceptions import PermissionDenied
from functools import wraps
from django.shortcuts import redirect

def role_required(*roles):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Redirect unauthenticated users to login
            if not request.user.is_authenticated:
                return redirect('login')  # Redirects to the login page

            # Retrieve the user profile and check the role
            user_profile = getattr(request.user, 'userprofile', None)
            
            # Debugging (optional): Print user authentication status and role
            print(f"Authenticated: {request.user.is_authenticated}, Role: {getattr(user_profile, 'role', None)}")
            
            # Allow access if the user has an appropriate role
            if user_profile and user_profile.role in roles:
                return view_func(request, *args, **kwargs)

            # Deny access if the role is not authorized
            raise PermissionDenied  # Return a 403 response if the role is not authorized
        return _wrapped_view
    return decorator
