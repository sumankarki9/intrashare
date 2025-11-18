from django.contrib import admin
from .models import AppSettings, Profile, UserFile

# -------------------------
# App Settings Admin
# -------------------------
@admin.register(AppSettings)
class AppSettingsAdmin(admin.ModelAdmin):
    list_display = ('max_file_size_mb', 'allowed_file_types', 'updated_at')
    fields = ('max_file_size', 'allowed_file_types')  # editable fields
    readonly_fields = ('updated_at',)

    def max_file_size_mb(self, obj):
        """Display max file size in MB"""
        return f"{obj.max_file_size // (1024*1024)} MB"
    max_file_size_mb.short_description = "Max File Size"

# -------------------------
# User File Admin
# -------------------------
@admin.register(UserFile)
class UserFileAdmin(admin.ModelAdmin):
    list_display = ('file', 'uploader', 'uploaded_at')
    readonly_fields = ('uploaded_at',)
    search_fields = ('uploader__username', 'file')

# -------------------------
# User Profile Admin
# -------------------------
@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'device_name', 'ip_address', 'created_at')
    readonly_fields = ('created_at',)
    search_fields = ('user__username', 'device_name', 'ip_address')
