"""intrashare URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from user.views import custom_admin_dashboard, delete_user, toggle_user_status

urlpatterns = [
    # Django default admin panel
    path('admin/', admin.site.urls),
    
    # Custom admin dashboard and admin actions
    path('wadmin/', custom_admin_dashboard, name='custom_admin_dashboard'),
    path('delete-user/<int:user_id>/', delete_user, name='delete_user'),
    path('toggle-user/<int:user_id>/', toggle_user_status, name='toggle_user_status'),
    
    # All user app routes (home, login, register, dashboard, etc.)
    path('', include('user.urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)