from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, Http404
from .forms import RegisterForm, FileUploadForm
from .models import UserFile
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
            user = form.save()
            login(request, user)
            return redirect('dashboard')
        else:
            # Sequential error handling: show only the first error
            for field in form.fields:
                if form[field].errors:
                    if field == 'username':
                        form.data = form.data.copy()
                        form.data['username'] = ''
                    for f in form.fields:
                        if f != field:
                            form[f].errors.clear()
                    break
    else:
        form = RegisterForm()

    return render(request, "auth/register.html", {"form": form})


@login_required
def dashboard(request):
    query = request.GET.get('q', '')
    if query:
        files = UserFile.objects.filter(
            Q(file__icontains=query) | Q(uploader__username__icontains=query)
        ).order_by('-uploaded_at')
    else:
        files = UserFile.objects.all().order_by('-uploaded_at')

    if request.method == "POST":
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            f = form.save(commit=False)
            f.uploader = request.user  # Make sure your UserFile model has 'uploader' field
            f.save()
            return redirect('dashboard')
    else:
        form = FileUploadForm()

    return render(request, "dashboard.html", {"files": files, "form": form, "query": query})


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


def logout_view(request):
    logout(request)
    return redirect('home')
