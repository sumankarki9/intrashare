
from django.urls import path
from .forms import LoginForm
# from .views import 
from .views import home, register_view, dashboard, logout_view
from django.contrib.auth import views as auth_views
from .views import register_view, dashboard, logout_view, download_file

urlpatterns = [
    path('', home, name="home"),
    path('register/', register_view, name="register"),

    path('login/', auth_views.LoginView.as_view(template_name='auth/login.html', authentication_form=LoginForm), name='login'),
    # path('login/', auth_views.LoginView.as_view(template_name="auth/login.html"), name='login'),
    path('logout/', logout_view, name='logout'),
    path('dashboard/', dashboard, name='dashboard'),
    path('download/<int:file_id>/', download_file, name='download_file'),

]
