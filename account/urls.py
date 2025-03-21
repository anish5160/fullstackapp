from django.urls import path
from account.views import (
    UserRegistrationView, 
    UserLoginView, 
    UserProfileView, 
    UserChangePasswordView, 
    SendPasswordResetEmailView, 
    UserPasswordResetView,
    AttendanceView  # New AttendanceView added
)

# URL Patterns for User Account and Attendance Management
urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='user_register'),
    path('login/', UserLoginView.as_view(), name='user_login'),
    path('profile/', UserProfileView.as_view(), name='user_profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name='user_change_password'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send_reset_password_email'),
    path('reset-password/<str:uid>/<str:token>/', UserPasswordResetView.as_view(), name='user_reset_password'),

    path('attendance/', AttendanceView.as_view(), name='user_attendance'),  
    path("attendance/<str:subject>/", AttendanceView.as_view(), name="delete_attendance"),

    
]
