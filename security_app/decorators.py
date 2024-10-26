# security_app/decorators.py
from functools import wraps
from django.shortcuts import render, redirect

def role_required(*roles):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Redirect unauthenticated users to login
            if not request.user.is_authenticated:
                return redirect('login')  # Redirects to the login page

            # Retrieve the user profile and check the role
            user_profile = getattr(request.user, 'userprofile', None)
            
            # Debugging: Print user authentication status and role
            print(f"Authenticated: {request.user.is_authenticated}, Username: {request.user.username}, Role: {getattr(user_profile, 'role', 'None')}")
            
            # Check for missing profile and unauthorized roles
            if user_profile and user_profile.role in roles:
                return view_func(request, *args, **kwargs)
            elif not user_profile:
                print("Warning: UserProfile is missing for the user.")
                return render(request, 'security_app/permission_denied.html', {"message": "Profile setup incomplete. Please contact an administrator."})
            else:
                return render(request, 'security_app/permission_denied.html', {"message": "You do not have permission to access this page."})
        
        return _wrapped_view
    return decorator
