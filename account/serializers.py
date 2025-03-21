from rest_framework import serializers
from account.models import User, Attendance
from django.contrib.auth.password_validation import validate_password
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse
from account.utils import Util
from django.core.exceptions import ObjectDoesNotExist
from datetime import datetime   
# User Registration Serializer
class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'name', 'password', 'password2', 'tc']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password don't match.")
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')  # Remove password2 as it's not part of the User model
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)  # Hash the password
        user.save()
        return user



# User Login Serializer
class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(write_only=True)


# User Profile Serializer
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name']


# Change Password Serializer
class UserChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    def validate(self, attrs):
        current_password = attrs.get('current_password')
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')

        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password don't match.")
        if not user.check_password(current_password):
            raise serializers.ValidationError("Current password is incorrect.")
       
        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    def validate(self, attrs):
        email = attrs.get('email')
        print(f"Received email: {email}")  # Debugging line
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            
            full_link = f'http://localhost:3000/reset-password/{uid}/{token}/'
            print(f"Generated reset link: {full_link}")  # Debugging line
            
            body = f'Click the following link to reset your password: {full_link}'
            data = {
                'subject': 'Reset Your Password',
                'body': body,
                'to_email': user.email
            }
            Util.send_email(data)  # Ensure this line is uncommented
            
            return attrs
        else:
            raise serializers.ValidationError('You are not a registered user.')


# User Password Reset Serializer
class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True
    )
    password2 = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True
    )

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')

            if password != password2:
                raise serializers.ValidationError("Passwords do not match.")

            user_id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError("Invalid or expired token.")

            validate_password(password, user)

            user.set_password(password)
            user.save()

            return attrs

        except DjangoUnicodeDecodeError as e:
            print(f"❌ Decode error: {str(e)}")
            raise serializers.ValidationError("Invalid token format.")

        except ObjectDoesNotExist:
            print("❌ User not found.")
            raise serializers.ValidationError("User not found.")

        except Exception as e:
            print(f"❌ Unknown error: {str(e)}")
            raise serializers.ValidationError("Something went wrong.")


# Attendance Serializer
class AttendanceSerializer(serializers.ModelSerializer):
    user = serializers.CharField(source="user.username", read_only=True)
    
    class Meta:
        model = Attendance
        fields = ['id', 'user', 'subject', 'date', 'status']
        extra_kwargs = {
            'subject': {'required': True, 'allow_blank': False},
            'date': {'required': True},
            'status': {'required': True}
        }

    def validate_status(self, value):
        value = value.lower()
        if value not in ['present', 'absent', 'clear']:
            raise serializers.ValidationError("Invalid status value")
        return value

    def validate_date(self, value):
        if isinstance(value, str):  
            try:
                return datetime.strptime(value, '%Y-%m-%d').date()
            except ValueError:
                raise serializers.ValidationError("Invalid date format. Use YYYY-MM-DD.")
        return value  

    def validate_subject(self, value):
        if not value.strip():
            raise serializers.ValidationError("Subject cannot be empty")
        return value.strip()

    def create(self, validated_data):
        """Allow updating attendance instead of rejecting duplicates."""
        user = self.context['request'].user
        subject = validated_data['subject']
        date = validated_data['date']
        
        # Check if attendance already exists
        attendance_entry = Attendance.objects.filter(user=user, subject=subject, date=date).first()

        if attendance_entry:
            # Update existing attendance instead of rejecting
            attendance_entry.status = validated_data['status']
            attendance_entry.save()
            return attendance_entry  # Return updated instance

        return super().create(validated_data)
