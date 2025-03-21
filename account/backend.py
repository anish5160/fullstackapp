from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
User = get_user_model()

class CustomUserBackend(BaseBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
       
        print(f"Authenticating {email}...")

        try:
            user = User.objects.get(email=email)
            print(f"User found: {user}")
            if user.check_password(password):  # Verifies the password using the hashed value
                print("Password matched!")
                return user
            print("Password did not match.")
        except User.DoesNotExist:
            print("User not found.")
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
