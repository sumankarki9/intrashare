from django.db import models
from django.contrib.auth.models import User

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
# File Upload / Sharing
# -------------------------
class UserFile(models.Model):
    uploader = models.ForeignKey(User, on_delete=models.CASCADE)  # consistent with views
    file = models.FileField(upload_to='uploads/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.file.name} by {self.uploader.username}"
