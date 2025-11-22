from django.urls import path
from .views import (
    home, 
    register_view, 
    dashboard, 
    logout_view, 
    download_file,
    delete_file,
    custom_login_view,
    toggle_user_status
)

urlpatterns = [
    path('', home, name="home"),
    path('register/', register_view, name="register"),
    path('login/', custom_login_view, name="login"),
    path('logout/', logout_view, name='logout'),
    path('dashboard/', dashboard, name='dashboard'),
    path('download/<int:file_id>/', download_file, name='download_file'),
    path('delete/<int:file_id>/', delete_file, name='delete_file'),
    path('toggle-user/<int:user_id>/', toggle_user_status, name='toggle_user_status'),
]