from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.db.models import Count, Q
from collections import defaultdict
from datetime import datetime
from django.shortcuts import get_object_or_404
import json
from rest_framework.parsers import JSONParser
from rest_framework.authentication import TokenAuthentication

from account.serializers import (
    SendPasswordResetEmailSerializer, UserChangePasswordSerializer,
    UserLoginSerializer, UserPasswordResetSerializer, UserProfileSerializer,
    UserRegistrationSerializer, AttendanceSerializer
)
from account.models import Attendance
from account.renderers import UserRenderer
from datetime import datetime
from django.db import IntegrityError

# Token Generator
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {'refresh': str(refresh), 'access': str(refresh.access_token)}

# User Registration
class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            'token': get_tokens_for_user(user),
            'msg': 'Registration Successful',
            'user': UserProfileSerializer(user).data
        }, status=status.HTTP_201_CREATED)

# User Login
class UserLoginView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(**serializer.validated_data)
        if user:
            return Response({
                'token': get_tokens_for_user(user),
                'msg': 'Login Successful',
                'user': UserProfileSerializer(user).data
            }, status=status.HTTP_200_OK)
        return Response({'errors': {'non_field_errors': ['Invalid Email or Password']}}, status=status.HTTP_401_UNAUTHORIZED)

# User Profile
class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserProfileSerializer(request.user).data, status=status.HTTP_200_OK)

# Change Password
class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = UserChangePasswordSerializer(data=request.data, context={'user': request.user})
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password Changed Successfully'}, status=status.HTTP_200_OK)

# Password Reset
class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password Reset Link Sent. Please Check Your Email'}, status=status.HTTP_200_OK)
class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [AllowAny]

    
    def post(self, request, uid, token):
        print(f"🔹 Received reset request for UID: {uid}, Token: {token}")

        serializer = UserPasswordResetSerializer(
            data=request.data, context={'uid': uid, 'token': token}
        )
        serializer.is_valid(raise_exception=True)

        return Response({"msg": "Password reset successful!"}, status=status.HTTP_200_OK)


class AttendanceView(APIView):

    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Handle array input
        serializer = AttendanceSerializer(
            data=request.data.get('attendance', []),
            many=True,
            context={'request': request}
        )
        
        if serializer.is_valid():
            # Create attendance records with user
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
            
        return Response({
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    def get(self, request):
        """Retrieve attendance records for a user with calendar visualization support."""
        user = request.user
        subject = request.query_params.get("subject")

        # Filter attendance records
        attendance_filter = {"user": user}
        if subject:
            attendance_filter["subject"] = subject

        attendance_records = Attendance.objects.filter(**attendance_filter)

        # Construct calendar data
        calendar_data = defaultdict(dict)
        for record in attendance_records:
            calendar_data[record.date.isoformat()][record.subject] = record.status

        # Calculate attendance percentages
        subject_counts = attendance_records.values("subject").annotate(
            total=Count("id"),  # Count all attendance records per subject
            present=Count("id", filter=Q(status="Present"))  # Count only "Present"
        )

        percentage_data = {
            item["subject"]: round((item["present"] / item["total"]) * 100, 2) if item["total"] > 0 else 0.0
            for item in subject_counts
        }

        return Response({
            "attendance_calendar": calendar_data,
            "attendance_percentage_per_subject": percentage_data
        }, status=status.HTTP_200_OK)


    def delete(self, request, subject):
        """Delete all attendance records for a given subject."""
        if not subject:
            return Response({"message": "Subject is required"}, status=status.HTTP_400_BAD_REQUEST)

        attendance_entries = Attendance.objects.filter(user=request.user, subject=subject)
        if attendance_entries.exists():
            attendance_entries.delete()
            return Response({"message": f"All attendance records for {subject} deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

        return Response({"message": "No attendance records found for the given subject"}, status=status.HTTP_404_NOT_FOUND)
