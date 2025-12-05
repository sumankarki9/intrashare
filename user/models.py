from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
import random
import string

# -------------------------
# User Profile (Optional)
# -------------------------
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    device_name = models.CharField(max_length=100, blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.username


# -------------------------
# App Settings
# -------------------------
class AppSettings(models.Model):
    max_file_size = models.PositiveIntegerField(
        default=1048576,  # 1 MB default
        help_text="Maximum allowed file size in bytes"
    )
    allowed_file_types = models.CharField(
        max_length=255,
        default="*",
        help_text="Comma-separated list of allowed file extensions. Use '*' for all."
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "App Settings"
        verbose_name_plural = "App Settings"

    def __str__(self):
        return f"App Settings (Max Size: {self.max_file_size / (1024 * 1024):.2f} MB)"


# -------------------------
# File Upload / Sharing
# -------------------------
class UserFile(models.Model):
    uploader = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to='uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    # Expiry time fields
    expiry_days = models.PositiveIntegerField(default=0, help_text="Days until expiry")
    expiry_hours = models.PositiveIntegerField(default=0, help_text="Hours until expiry")
    expiry_minutes = models.PositiveIntegerField(default=0, help_text="Minutes until expiry")
    expiry_seconds = models.PositiveIntegerField(default=0, help_text="Seconds until expiry")
    never_expire = models.BooleanField(default=True, help_text="File never expires")
    
    expires_at = models.DateTimeField(
        null=True, 
        blank=True,
        help_text="Calculated expiration date/time"
    )

    class Meta:
        ordering = ['-uploaded_at']
        verbose_name = "User File"
        verbose_name_plural = "User Files"

    def __str__(self):
        return f"{self.file.name} by {self.uploader.username}"

    def calculate_expiry(self):
        """Calculate and set the expiry date based on time fields"""
        if self.never_expire:
            self.expires_at = None
            return
        
        # Calculate total time delta from all fields
        total_time = timedelta(
            days=self.expiry_days or 0,
            hours=self.expiry_hours or 0,
            minutes=self.expiry_minutes or 0,
            seconds=self.expiry_seconds or 0
        )
        
        # Check if any time is actually set
        if total_time.total_seconds() > 0:
            # Set expiry based on current time + delta
            self.expires_at = timezone.now() + total_time
        else:
            # No time set - default to 7 days
            self.expires_at = timezone.now() + timedelta(days=7)

    def save(self, *args, **kwargs):
        """Calculate expiry before saving"""
        self.calculate_expiry()
        super().save(*args, **kwargs)

    def is_expired(self):
        """Check if the file has expired"""
        if self.never_expire or not self.expires_at:
            return False
        return timezone.now() > self.expires_at

    def time_until_expiry(self):
        """Return human-readable time until expiry"""
        if self.never_expire or not self.expires_at:
            return "Never expires"
        
        if self.is_expired():
            return "Expired"
        
        time_left = self.expires_at - timezone.now()
        
        # Handle negative time (expired)
        if time_left.total_seconds() < 0:
            return "Expired"
        
        days = time_left.days
        hours = time_left.seconds // 3600
        minutes = (time_left.seconds % 3600) // 60
        seconds = time_left.seconds % 60
        
        # Format display based on largest unit
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def get_expiry_time_string(self):
        """Get the expiry time as a string for display"""
        if self.never_expire:
            return "Never"
        parts = []
        if self.expiry_days:
            parts.append(f"{self.expiry_days}d")
        if self.expiry_hours:
            parts.append(f"{self.expiry_hours}h")
        if self.expiry_minutes:
            parts.append(f"{self.expiry_minutes}m")
        if self.expiry_seconds:
            parts.append(f"{self.expiry_seconds}s")
        return " ".join(parts) if parts else "Not set"
    

class PasswordResetOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self.expires_at:
            # OTP expires in 10 minutes
            self.expires_at = timezone.now() + timedelta(minutes=10)
        super().save(*args, **kwargs)

    def is_valid(self):
        """Check if OTP is still valid (not expired and not used)"""
        return not self.is_used and timezone.now() < self.expires_at

    @staticmethod
    def generate_otp():
        """Generate a 6-digit OTP"""
        return ''.join(random.choices(string.digits, k=6))

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Password Reset OTP'
        verbose_name_plural = 'Password Reset OTPs'

    def __str__(self):
        return f"OTP for {self.user.username} - {'Used' if self.is_used else 'Valid' if self.is_valid() else 'Expired'}"