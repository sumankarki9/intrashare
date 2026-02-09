from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, Http404
from .forms import RegisterForm, FileUploadForm
from .models import UserFile, AppSettings
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
import os
from django.db.models import Q
from django.utils import timezone
from datetime import timedelta
from .utils import (
    send_registration_email_to_admin,
    send_registration_confirmation_to_user,
    send_account_approved_email,
    send_account_deactivated_email,
    send_password_reset_otp
)
from .models import UserFile, AppSettings, PasswordResetOTP, FileShare

def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard') 
    return render(request, "home.html")

def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            
            # Send emails
            send_registration_email_to_admin(user)
            send_registration_confirmation_to_user(user)
            
            return render(request, "auth/register_success.html", {"user": user})
        else:
            for field in form.fields:
                if form[field].errors:
                    form.data = form.data.copy()
                    if field == 'username':
                        form.data['username'] = ''
                    for f in form.fields:
                        if f != field:
                            form[f].errors.clear()
                    break
    else:
        form = RegisterForm()

    return render(request, "auth/register.html", {"form": form})

@login_required
def download_file(request, file_id):
    file = get_object_or_404(UserFile, id=file_id)
    file_path = file.file.path
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            response = HttpResponse(f.read(), content_type="application/octet-stream")
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
    raise Http404

@login_required
def delete_file(request, file_id):
    """Delete a file - only owner or admin can delete"""
    if request.method == "POST":
        try:
            user_file = UserFile.objects.get(id=file_id)
            
            # Permission check: only uploader or admin can delete
            if user_file.uploader != request.user and not request.user.is_superuser:
                messages.error(request, "You don't have permission to delete this file.")
                return redirect('dashboard')
            
            # Store filename for message
            filename = user_file.file.name
            
            # Delete the file from storage and database
            user_file.file.delete(save=False)
            user_file.delete()
            
            messages.success(request, f"File '{os.path.basename(filename)}' deleted successfully.")
            
        except UserFile.DoesNotExist:
            messages.error(request, "File not found.")
        except Exception as e:
            messages.error(request, f"Error deleting file: {str(e)}")
    
    return redirect('dashboard')

def custom_login_view(request):
    # Redirect if already logged in
    if request.user.is_authenticated:
        if request.user.is_superuser:
            # Check if coming from wadmin
            next_url = request.GET.get('next', '')
            if 'wadmin' in next_url:
                return redirect('custom_admin_dashboard')
        return redirect('dashboard')
    
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        next_url = request.POST.get("next", "")

        try:
            db_user = User.objects.get(username=username)
            if not db_user.is_active:
                messages.error(request, "Your account is under admin review. Please wait for approval.")
                return render(request, "auth/login.html", {"next": next_url})
        except User.DoesNotExist:
            db_user = None

        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Check if trying to access wadmin without superuser privileges
            if 'wadmin' in next_url and not user.is_superuser:
                messages.error(request, "You don't have permission to access the admin panel.")
                return render(request, "auth/login.html", {"next": next_url})
            
            login(request, user)
            
            # Redirect to next URL or default dashboard
            if next_url and next_url != '/':
                return redirect(next_url)
            return redirect("dashboard")
        else:
            messages.error(request, "Invalid username or password.")
            return render(request, "auth/login.html", {"next": next_url})

    # GET request - check if redirected from wadmin
    next_url = request.GET.get('next', '')
    return render(request, "auth/login.html", {"next": next_url})

@user_passes_test(lambda u: u.is_superuser, login_url='/login/?next=/wadmin/')
def toggle_user_status(request, user_id):
    user = get_object_or_404(User, id=user_id)

    if user == request.user:
        messages.error(request, "You cannot deactivate your own account.")
        return redirect("custom_admin_dashboard")

    # Store previous state
    was_active = user.is_active
    
    # Toggle status
    user.is_active = not user.is_active
    user.save()

    # Send appropriate email
    if user.is_active:
        # Account was activated
        send_account_approved_email(user)
        messages.success(request, f"{user.username} has been activated. Approval email sent.")
    else:
        # Account was deactivated
        send_account_deactivated_email(user)
        messages.warning(request, f"{user.username} has been deactivated. Notification email sent.")

    return redirect("custom_admin_dashboard")

@user_passes_test(lambda u: u.is_superuser, login_url='/login/?next=/wadmin/')
def delete_user(request, user_id):
    """Delete a user permanently"""
    if request.method == "POST":
        user = get_object_or_404(User, id=user_id)
        
        # Prevent admin from deleting themselves
        if user == request.user:
            messages.error(request, "You cannot delete your own account.")
            return redirect("custom_admin_dashboard")
        
        # Delete user's files first
        user_files = UserFile.objects.filter(uploader=user)
        file_count = user_files.count()
        
        # Delete all user's files
        for file in user_files:
            file.file.delete(save=False)
            file.delete()
        
        username = user.username
        user.delete()
        
        messages.success(request, f"User '{username}' and {file_count} file(s) deleted permanently.")
        return redirect("custom_admin_dashboard")
    
    return redirect("custom_admin_dashboard")

@user_passes_test(lambda u: u.is_superuser, login_url='/login/?next=/wadmin/')
def custom_admin_dashboard(request):
    settings, created = AppSettings.objects.get_or_create(
        defaults={'max_file_size': 1048576}  # 1 MB default
    )
    users = User.objects.all().order_by('username')

    max_file_size_mb = settings.max_file_size // 1048576

    if request.method == "POST":
        max_size = request.POST.get("max_file_size")

        if max_size:
            try:
                max_size_int = int(max_size)
                if max_size_int > 0:
                    settings.max_file_size = max_size_int * 1024 * 1024
                    settings.save()
                    max_file_size_mb = settings.max_file_size // 1048576
                    messages.success(request, f"Max file size updated to {max_size_int} MB.")
                else:
                    messages.error(request, "File size must be greater than 0.")
            except ValueError:
                messages.error(request, "Invalid file size value.")
        
        return redirect('custom_admin_dashboard')

    return render(request, "auth/custom_admin.html", {
        "users": users,
        "settings": settings,
        "max_file_size_mb": max_file_size_mb
    })

def logout_view(request):
    logout(request)
    return redirect('home')

@login_required
def dashboard(request):
    settings = AppSettings.objects.first()
    max_file_size_mb = settings.max_file_size / (1024 * 1024) if settings else 1
    max_file_size_bytes = settings.max_file_size if settings else 1048576

    query = request.GET.get('q', '')

    # Get files uploaded by current user OR shared with current user
    if query:
        # Files uploaded by user
        my_files = UserFile.objects.filter(
            uploader=request.user
        ).filter(
            Q(file__icontains=query) | Q(uploader__username__icontains=query)
        )
        
        # Files shared with user
        shared_file_ids = FileShare.objects.filter(
            shared_with=request.user
        ).values_list('file_id', flat=True)
        
        shared_files = UserFile.objects.filter(
            id__in=shared_file_ids
        ).filter(
            Q(file__icontains=query) | Q(uploader__username__icontains=query)
        )
        
        files = (my_files | shared_files).distinct().order_by('-uploaded_at')
    else:
        # Files uploaded by user
        my_files = UserFile.objects.filter(uploader=request.user)
        
        # Files shared with user
        shared_file_ids = FileShare.objects.filter(
            shared_with=request.user
        ).values_list('file_id', flat=True)
        
        shared_files = UserFile.objects.filter(id__in=shared_file_ids)
        
        files = (my_files | shared_files).distinct().order_by('-uploaded_at')

    # Filter out expired files
    active_files = []
    for file in files:
        if file.is_expired():
            pass  # Skip expired files (just hide them)
        else:
            active_files.append(file)
    
    files = active_files
    
    # Get all active users for sharing (exclude current user)
    all_users = User.objects.filter(is_active=True).exclude(id=request.user.id).order_by('username')

    if request.method == "POST":
        if 'file' in request.FILES:
            # New file upload
            uploaded_file = request.FILES['file']
            
            # Server-side file size validation
            if uploaded_file.size > max_file_size_bytes:
                messages.error(request, f"File too large! Maximum allowed size is {max_file_size_mb:.2f} MB.")
                return redirect('dashboard')
            
            # Get form data
            never_expire = request.POST.get('never_expire') == 'on'
            
            # Create file instance manually
            user_file = UserFile()
            user_file.file = uploaded_file
            user_file.uploader = request.user
            user_file.never_expire = never_expire
            
            if not never_expire:
                # Get time values
                user_file.expiry_days = int(request.POST.get('expiry_days', 0) or 0)
                user_file.expiry_hours = int(request.POST.get('expiry_hours', 0) or 0)
                user_file.expiry_minutes = int(request.POST.get('expiry_minutes', 0) or 0)
                user_file.expiry_seconds = int(request.POST.get('expiry_seconds', 0) or 0)
            else:
                # Reset all time fields to 0 when never expire
                user_file.expiry_days = 0
                user_file.expiry_hours = 0
                user_file.expiry_minutes = 0
                user_file.expiry_seconds = 0
            
            # Save (this will trigger calculate_expiry in model)
            user_file.save()
            
            # Handle sharing with specific users
            shared_users = request.POST.getlist('shared_users')
            if shared_users:
                for user_id in shared_users:
                    try:
                        user = User.objects.get(id=user_id, is_active=True)
                        FileShare.objects.create(
                            file=user_file,
                            shared_with=user,
                            shared_by=request.user
                        )
                    except User.DoesNotExist:
                        pass
                
                if user_file.never_expire:
                    messages.success(request, f"File uploaded and shared with {len(shared_users)} user(s)! Expiry: Never")
                else:
                    messages.success(request, f"File uploaded and shared with {len(shared_users)} user(s)! Expiry: {user_file.get_expiry_time_string()}")
            else:
                if user_file.never_expire:
                    messages.success(request, "File uploaded successfully! Expiry: Never")
                else:
                    messages.success(request, f"File uploaded successfully! Expiry: {user_file.get_expiry_time_string()}")
            
            return redirect('dashboard')

        elif 'update_file' in request.FILES or 'file_id' in request.POST:
            # Update existing file (file is now optional)
            try:
                file_id = int(request.POST['file_id'])
                user_file = UserFile.objects.get(id=file_id)
                
                # Permission check: only uploader or admin can update
                if user_file.uploader != request.user and not request.user.is_superuser:
                    messages.error(request, "You don't have permission to update this file.")
                    return redirect('dashboard')
                
                # Check if new file is uploaded
                if 'update_file' in request.FILES:
                    new_file = request.FILES['update_file']
                    
                    # Server-side file size validation
                    if new_file.size > max_file_size_bytes:
                        messages.error(request, f"File too large! Maximum allowed size is {max_file_size_mb:.2f} MB.")
                        return redirect('dashboard')
                    
                    # Delete old file and upload new one
                    user_file.file.delete(save=False)
                    user_file.file = new_file
                
                # Update expiry settings (always update, even if no new file)
                never_expire = request.POST.get('never_expire') == 'on'
                user_file.never_expire = never_expire
                
                if not never_expire:
                    user_file.expiry_days = int(request.POST.get('expiry_days', 0) or 0)
                    user_file.expiry_hours = int(request.POST.get('expiry_hours', 0) or 0)
                    user_file.expiry_minutes = int(request.POST.get('expiry_minutes', 0) or 0)
                    user_file.expiry_seconds = int(request.POST.get('expiry_seconds', 0) or 0)
                else:
                    user_file.expiry_days = 0
                    user_file.expiry_hours = 0
                    user_file.expiry_minutes = 0
                    user_file.expiry_seconds = 0
                
                # Save will recalculate expiry
                user_file.save()
                
                # Update sharing
                shared_users = request.POST.getlist('shared_users')
                if shared_users:
                    # Remove old shares
                    FileShare.objects.filter(file=user_file).delete()
                    
                    # Add new shares
                    for user_id in shared_users:
                        try:
                            user = User.objects.get(id=user_id, is_active=True)
                            FileShare.objects.create(
                                file=user_file,
                                shared_with=user,
                                shared_by=request.user
                            )
                        except User.DoesNotExist:
                            pass
                
                if 'update_file' in request.FILES:
                    messages.success(request, f"File and expiry updated successfully.")
                else:
                    messages.success(request, f"Expiry time updated successfully.")
                
                return redirect('dashboard')
                
            except UserFile.DoesNotExist:
                messages.error(request, "File not found.")
            except ValueError as e:
                messages.error(request, f"Invalid input: {str(e)}")
            except Exception as e:
                messages.error(request, f"Error updating: {str(e)}")
            
            return redirect('dashboard')

    form = FileUploadForm()

    return render(request, "dashboard.html", {
        "files": files,
        "form": form,
        "query": query,
        "settings": settings,
        "max_file_size_mb": max_file_size_mb,
        "all_users": all_users,
    })


def forgot_password(request):
    """Step 1: Request password reset - send OTP"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == "POST":
        identifier = request.POST.get("identifier", "").strip()
        
        if not identifier:
            messages.error(request, "Please enter your username or email.")
            return render(request, "auth/forgot_password.html")
        
        # Find user by username or email
        user = None
        try:
            user = User.objects.get(username=identifier)
        except User.DoesNotExist:
            try:
                user = User.objects.get(email=identifier)
            except User.DoesNotExist:
                pass
        
        if not user:
            messages.error(request, "No account found with that username or email.")
            return render(request, "auth/forgot_password.html")
        
        if not user.email:
            messages.error(request, "This account has no email address registered. Please contact the administrator.")
            return render(request, "auth/forgot_password.html")
        
        # Check for recent OTP requests (rate limiting)
        recent_otp = PasswordResetOTP.objects.filter(
            user=user,
            created_at__gte=timezone.now() - timedelta(minutes=2)
        ).first()
        
        if recent_otp:
            messages.warning(request, "Please wait 2 minutes before requesting another OTP.")
            return render(request, "auth/forgot_password.html")
        
        # Generate and save OTP
        otp_code = PasswordResetOTP.generate_otp()
        PasswordResetOTP.objects.create(user=user, otp=otp_code)
        
        # Send OTP email
        if send_password_reset_otp(user, otp_code):
            messages.success(request, f"An OTP has been sent to {user.email}. Please check your inbox.")
            # Store username in session for next step
            request.session['reset_username'] = user.username
            return redirect('verify_otp')
        else:
            messages.error(request, "Failed to send OTP. Please try again later.")
            return render(request, "auth/forgot_password.html")
    
    return render(request, "auth/forgot_password.html")


def verify_otp(request):
    """Step 2: Verify OTP"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    username = request.session.get('reset_username')
    if not username:
        messages.error(request, "Session expired. Please start the password reset process again.")
        return redirect('forgot_password')
    
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        messages.error(request, "User not found.")
        return redirect('forgot_password')
    
    if request.method == "POST":
        otp_input = request.POST.get("otp", "").strip()
        
        if not otp_input:
            messages.error(request, "Please enter the OTP.")
            return render(request, "auth/verify_otp.html", {"email": user.email})
        
        # Find valid OTP
        otp_record = PasswordResetOTP.objects.filter(
            user=user,
            otp=otp_input,
            is_used=False
        ).order_by('-created_at').first()
        
        if not otp_record:
            messages.error(request, "Invalid OTP. Please try again.")
            return render(request, "auth/verify_otp.html", {"email": user.email})
        
        if not otp_record.is_valid():
            messages.error(request, "OTP has expired. Please request a new one.")
            return redirect('forgot_password')
        
        # OTP is valid - mark as used and proceed to password reset
        otp_record.is_used = True
        otp_record.save()
        
        # Store OTP ID in session for verification in next step
        request.session['verified_otp_id'] = otp_record.id
        messages.success(request, "OTP verified successfully. Please set your new password.")
        return redirect('reset_password')
    
    return render(request, "auth/verify_otp.html", {"email": user.email})


def reset_password(request):
    """Step 3: Set new password"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    username = request.session.get('reset_username')
    verified_otp_id = request.session.get('verified_otp_id')
    
    if not username or not verified_otp_id:
        messages.error(request, "Session expired. Please start the password reset process again.")
        return redirect('forgot_password')
    
    try:
        user = User.objects.get(username=username)
        otp_record = PasswordResetOTP.objects.get(id=verified_otp_id, user=user, is_used=True)
    except (User.DoesNotExist, PasswordResetOTP.DoesNotExist):
        messages.error(request, "Invalid session. Please start again.")
        return redirect('forgot_password')
    
    if request.method == "POST":
        new_password = request.POST.get("new_password", "")
        confirm_password = request.POST.get("confirm_password", "")
        
        if not new_password or not confirm_password:
            messages.error(request, "Please fill in both password fields.")
            return render(request, "auth/reset_password.html")
        
        if new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, "auth/reset_password.html")
        
        if len(new_password) < 8:
            messages.error(request, "Password must be at least 8 characters long.")
            return render(request, "auth/reset_password.html")
        
        # Set new password
        user.set_password(new_password)
        user.save()
        
        # Clean up session
        del request.session['reset_username']
        del request.session['verified_otp_id']
        
        messages.success(request, "Password reset successful! You can now login with your new password.")
        return redirect('login')
    
    return render(request, "auth/reset_password.html")