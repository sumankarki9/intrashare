from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from .models import UserFile
from django.core.exceptions import ValidationError
from .models import AppSettings

class RegisterForm(UserCreationForm):
    email = forms.EmailField(
        required=True, 
        widget=forms.EmailInput(attrs={
            'class': 'w-full px-3 py-2 border rounded',
            'placeholder': 'Email address'
        })
    )
    
    username = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 border rounded',
            'placeholder': 'Username'
        })
    )
    
    password1 = forms.CharField(
        label="Password", 
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-3 py-2 border rounded',
            'placeholder': 'Password'
        })
    )
    
    password2 = forms.CharField(
        label="Confirm Password", 
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-3 py-2 border rounded',
            'placeholder': 'Confirm Password'
        })
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    # Sequential validation
    def clean(self):
        cleaned_data = super().clean()
        
        # 1️⃣ Validate username first
        username = cleaned_data.get('username')
        if username and User.objects.filter(username=username).exists():
            self.add_error('username', "A user with that username already exists.")
            # Stop further validation
            return cleaned_data
        
        # # 2️⃣ Validate email next
        # email = cleaned_data.get('email')
        # if email:
        #     try:
        #         forms.EmailField().clean(email)
        #     except forms.ValidationError:
        #         self.add_error('email', "Enter a valid email address.")
        #         return cleaned_data
        
# 2️⃣ Validate email next
        email = cleaned_data.get('email')
        if email:
            try:
                forms.EmailField().clean(email)
            except forms.ValidationError:
                self.add_error('email', "Enter a valid email address.")
                return cleaned_data
            
            # Check email uniqueness
            if User.objects.filter(email=email).exists():
                self.add_error('email', "An account with this email already exists.")
                return cleaned_data

class LoginForm(AuthenticationForm):
    username = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 border rounded',
            'placeholder': 'Username'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-3 py-2 border rounded',
            'placeholder': 'Password'
        })
    )

class FileUploadForm(forms.ModelForm):
    class Meta:
        model = UserFile
        fields = ['file']

    def clean_file(self):
        file = self.cleaned_data.get('file')
        settings = AppSettings.objects.first()
        max_size = settings.max_file_size if settings else 10485760  # 10 MB default

        if file.size > max_size:
            raise forms.ValidationError(
                f"File is too large. Maximum allowed size is {max_size / (1024*1024):.2f} MB."
            )

        return file
