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
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        try:
            db_user = User.objects.get(username=username)
            if not db_user.is_active:
                messages.error(request, "Your account is under admin review. Please wait for approval.")
                return render(request, "auth/login.html")
        except User.DoesNotExist:
            db_user = None

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect("dashboard")
        else:
            messages.error(request, "Invalid username or password.")
            return render(request, "auth/login.html")

    return render(request, "auth/login.html")

@user_passes_test(lambda u: u.is_superuser)
def toggle_user_status(request, user_id):
    user = get_object_or_404(User, id=user_id)

    if user == request.user:
        messages.error(request, "You cannot deactivate your own account.")
        return redirect("custom_admin_dashboard")

    user.is_active = not user.is_active
    user.save()

    if user.is_active:
        messages.success(request, f"{user.username} has been activated.")
    else:
        messages.warning(request, f"{user.username} has been deactivated.")

    return redirect("custom_admin_dashboard")

@user_passes_test(lambda u: u.is_superuser)
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

    if query:
        files = UserFile.objects.filter(
            Q(file__icontains=query) | Q(uploader__username__icontains=query)
        ).order_by('-uploaded_at')
    else:
        files = UserFile.objects.all().order_by('-uploaded_at')

    if request.method == "POST":
        if 'file' in request.FILES:
            # New file upload
            uploaded_file = request.FILES['file']
            
            # Server-side file size validation
            if uploaded_file.size > max_file_size_bytes:
                messages.error(request, f"File too large! Maximum allowed size is {max_file_size_mb:.2f} MB.")
                return redirect('dashboard')
            
            form = FileUploadForm(request.POST, request.FILES)
            if form.is_valid():
                f = form.save(commit=False)
                f.uploader = request.user
                f.save()
                messages.success(request, "File uploaded successfully.")
                return redirect('dashboard')
            else:
                messages.error(request, "Error uploading file. Please try again.")

        elif 'update_file' in request.FILES and 'file_id' in request.POST:
            # Update existing file
            try:
                file_id = int(request.POST['file_id'])
                user_file = UserFile.objects.get(id=file_id)
                
                # Permission check: only uploader or admin can update
                if user_file.uploader != request.user and not request.user.is_superuser:
                    messages.error(request, "You don't have permission to update this file.")
                    return redirect('dashboard')
                
                new_file = request.FILES['update_file']
                
                # Server-side file size validation
                if new_file.size > max_file_size_bytes:
                    messages.error(request, f"File too large! Maximum allowed size is {max_file_size_mb:.2f} MB.")
                    return redirect('dashboard')
                
                # Delete old file and save new one
                old_file_name = user_file.file.name
                user_file.file.delete(save=False)
                user_file.file = new_file
                user_file.save()
                
                messages.success(request, f"File updated successfully.")
                return redirect('dashboard')
                
            except UserFile.DoesNotExist:
                messages.error(request, "File not found.")
            except ValueError:
                messages.error(request, "Invalid file ID.")
            except Exception as e:
                messages.error(request, f"Error updating file: {str(e)}")
            
            return redirect('dashboard')

    form = FileUploadForm()

    return render(request, "dashboard.html", {
        "files": files,
        "form": form,
        "query": query,
        "settings": settings,
        "max_file_size_mb": max_file_size_mb,
    })