from django.contrib import admin
from account.models import User, Attendance  # Import Attendance model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin


class UserModelAdmin(BaseUserAdmin):
    list_display = ('id', 'email', 'name', 'tc', 'is_admin')
    list_filter = ('is_admin',)
    fieldsets = (
        ('User Credentials', {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('name', 'tc')}),
        ('Permissions', {'fields': ('is_admin',)}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'name', 'tc', 'password1', 'password2'),
        }),
    )
    search_fields = ('email',)
    ordering = ('email', 'id')
    filter_horizontal = ()


class AttendanceAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'date', 'subject', 'status', 'timestamp')
    list_filter = ('status', 'subject', 'date')  # Added subject to filters
    search_fields = ('user__email', 'date', 'subject')  # Allow searching by subject
    ordering = ('-date', 'user__email')
    readonly_fields = ('timestamp',)  # Make timestamp read-only

    def get_user_email(self, obj):
        return obj.user.email
    get_user_email.short_description = 'User Email'


# Register the models
admin.site.register(User, UserModelAdmin)
admin.site.register(Attendance, AttendanceAdmin)
