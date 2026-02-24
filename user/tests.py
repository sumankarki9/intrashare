"""
IntraShare - Full Test Suite
Run with: python manage.py test user.tests
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch, MagicMock
from django.db import transaction
import tempfile
import os

from user.models import UserFile, AppSettings, PasswordResetOTP, FileShare, Profile
from user.forms import RegisterForm


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_user(username='testuser', email='test@example.com', password='TestPass123!', is_active=True):
    user = User.objects.create_user(username=username, email=email, password=password)
    user.is_active = is_active
    user.save()
    return user

def create_superuser(username='admin', email='admin@example.com', password='AdminPass123!'):
    return User.objects.create_superuser(username=username, email=email, password=password)

def create_file(uploader, filename='test.txt', content=b'Hello World', never_expire=True):
    uploaded = SimpleUploadedFile(filename, content)
    user_file = UserFile.objects.create(
        uploader=uploader,
        file=uploaded,
        never_expire=never_expire,
    )
    return user_file


# =============================================================================
# MODEL TESTS
# =============================================================================

class ProfileModelTest(TestCase):

    def test_profile_str(self):
        user = create_user()
        profile = Profile.objects.create(user=user)
        self.assertEqual(str(profile), user.username)

    def test_profile_optional_fields(self):
        user = create_user()
        profile = Profile.objects.create(user=user)
        self.assertIsNone(profile.device_name)
        self.assertIsNone(profile.ip_address)


class AppSettingsModelTest(TestCase):

    def test_default_max_file_size(self):
        settings = AppSettings.objects.create()
        self.assertEqual(settings.max_file_size, 1048576)

    def test_str_representation(self):
        settings = AppSettings.objects.create(max_file_size=2097152)
        self.assertIn('2.00 MB', str(settings))

    def test_allowed_file_types_default(self):
        settings = AppSettings.objects.create()
        self.assertEqual(settings.allowed_file_types, '*')


class UserFileModelTest(TestCase):

    def setUp(self):
        self.user = create_user()

    def tearDown(self):
        # Clean up uploaded files
        for f in UserFile.objects.all():
            if f.file and os.path.exists(f.file.path):
                os.remove(f.file.path)

    def test_file_str(self):
        user_file = create_file(self.user)
        self.assertIn(self.user.username, str(user_file))

    def test_never_expire_default(self):
        user_file = create_file(self.user)
        self.assertTrue(user_file.never_expire)
        self.assertIsNone(user_file.expires_at)

    def test_file_not_expired_when_never_expire(self):
        user_file = create_file(self.user)
        self.assertFalse(user_file.is_expired())

    def test_file_expiry_calculated_correctly(self):
        uploaded = SimpleUploadedFile('exp.txt', b'data')
        user_file = UserFile.objects.create(
            uploader=self.user,
            file=uploaded,
            never_expire=False,
            expiry_days=1,
            expiry_hours=0,
            expiry_minutes=0,
            expiry_seconds=0,
        )
        self.assertIsNotNone(user_file.expires_at)
        self.assertFalse(user_file.is_expired())

    def test_expired_file_detected(self):
        uploaded = SimpleUploadedFile('expired.txt', b'data')
        user_file = UserFile.objects.create(
            uploader=self.user,
            file=uploaded,
            never_expire=False,
        )
        # Force expiry in the past
        user_file.expires_at = timezone.now() - timedelta(seconds=1)
        user_file.save()
        # Bypass calculate_expiry by setting directly
        UserFile.objects.filter(pk=user_file.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
        user_file.refresh_from_db()
        self.assertTrue(user_file.is_expired())

    def test_time_until_expiry_never_expires(self):
        user_file = create_file(self.user)
        self.assertEqual(user_file.time_until_expiry(), "Never expires")

    def test_time_until_expiry_future(self):
        uploaded = SimpleUploadedFile('future.txt', b'data')
        user_file = UserFile.objects.create(
            uploader=self.user,
            file=uploaded,
            never_expire=False,
            expiry_hours=2,
        )
        result = user_file.time_until_expiry()
        self.assertNotEqual(result, "Expired")
        self.assertNotEqual(result, "Never expires")

    def test_get_expiry_time_string_never(self):
        user_file = create_file(self.user)
        self.assertEqual(user_file.get_expiry_time_string(), "Never")

    def test_get_expiry_time_string_with_values(self):
        uploaded = SimpleUploadedFile('t.txt', b'data')
        user_file = UserFile.objects.create(
            uploader=self.user,
            file=uploaded,
            never_expire=False,
            expiry_days=1,
            expiry_hours=2,
        )
        result = user_file.get_expiry_time_string()
        self.assertIn('1d', result)
        self.assertIn('2h', result)

    def test_default_expiry_when_no_time_set(self):
        """When never_expire=False but no time is set, defaults to 7 days"""
        uploaded = SimpleUploadedFile('default.txt', b'data')
        user_file = UserFile.objects.create(
            uploader=self.user,
            file=uploaded,
            never_expire=False,
        )
        self.assertIsNotNone(user_file.expires_at)
        expected = timezone.now() + timedelta(days=7)
        diff = abs((user_file.expires_at - expected).total_seconds())
        self.assertLess(diff, 5)  # Within 5 seconds


class PasswordResetOTPModelTest(TestCase):

    def setUp(self):
        self.user = create_user()

    def test_otp_generation_is_6_digits(self):
        otp = PasswordResetOTP.generate_otp()
        self.assertEqual(len(otp), 6)
        self.assertTrue(otp.isdigit())

    def test_otp_expires_in_10_minutes(self):
        otp = PasswordResetOTP.objects.create(
            user=self.user,
            otp='123456',
        )
        diff = (otp.expires_at - otp.created_at).total_seconds()
        self.assertAlmostEqual(diff, 600, delta=5)

    def test_valid_otp(self):
        otp = PasswordResetOTP.objects.create(user=self.user, otp='123456')
        self.assertTrue(otp.is_valid())

    def test_used_otp_is_invalid(self):
        otp = PasswordResetOTP.objects.create(user=self.user, otp='123456', is_used=True)
        self.assertFalse(otp.is_valid())

    def test_expired_otp_is_invalid(self):
        otp = PasswordResetOTP.objects.create(user=self.user, otp='123456')
        otp.expires_at = timezone.now() - timedelta(minutes=1)
        otp.save()
        self.assertFalse(otp.is_valid())

    def test_otp_str(self):
        otp = PasswordResetOTP.objects.create(user=self.user, otp='123456')
        self.assertIn(self.user.username, str(otp))


class FileShareModelTest(TestCase):

    def setUp(self):
        self.owner = create_user(username='owner', email='owner@test.com')
        self.recipient = create_user(username='recipient', email='recipient@test.com')
        self.file = create_file(self.owner)

    def tearDown(self):
        for f in UserFile.objects.all():
            if f.file and os.path.exists(f.file.path):
                os.remove(f.file.path)

    def test_file_share_creation(self):
        share = FileShare.objects.create(
            file=self.file,
            shared_with=self.recipient,
            shared_by=self.owner,
        )
        self.assertEqual(str(share), f"{self.file.file.name} shared with {self.recipient.username}")

    def test_unique_together_constraint(self):
        FileShare.objects.create(file=self.file, shared_with=self.recipient, shared_by=self.owner)
        with self.assertRaises(Exception):
            with transaction.atomic():
                FileShare.objects.create(file=self.file, shared_with=self.recipient, shared_by=self.owner)


# =============================================================================
# FORM TESTS
# =============================================================================

class RegisterFormTest(TestCase):

    def get_valid_data(self, **kwargs):
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password1': 'StrongPass123!',
            'password2': 'StrongPass123!',
        }
        data.update(kwargs)
        return data

    def test_valid_form(self):
        form = RegisterForm(data=self.get_valid_data())
        self.assertTrue(form.is_valid(), form.errors)

    def test_duplicate_username(self):
        create_user(username='newuser', email='other@example.com')
        form = RegisterForm(data=self.get_valid_data())
        self.assertFalse(form.is_valid())
        self.assertIn('username', form.errors)

    def test_duplicate_email(self):
        create_user(username='other', email='newuser@example.com')
        form = RegisterForm(data=self.get_valid_data())
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)

    def test_invalid_email_format(self):
        form = RegisterForm(data=self.get_valid_data(email='not-an-email'))
        self.assertFalse(form.is_valid())

    def test_password_mismatch(self):
        form = RegisterForm(data=self.get_valid_data(password2='WrongPass123!'))
        self.assertFalse(form.is_valid())

    def test_empty_username(self):
        form = RegisterForm(data=self.get_valid_data(username=''))
        self.assertFalse(form.is_valid())

    def test_empty_email(self):
        form = RegisterForm(data=self.get_valid_data(email=''))
        self.assertFalse(form.is_valid())


# =============================================================================
# VIEW TESTS — AUTH
# =============================================================================

class HomeViewTest(TestCase):

    def test_unauthenticated_user_sees_home(self):
        response = self.client.get(reverse('home'))
        self.assertEqual(response.status_code, 200)

    def test_authenticated_user_redirected_to_dashboard(self):
        user = create_user()
        self.client.force_login(user)
        response = self.client.get(reverse('home'))
        self.assertRedirects(response, reverse('dashboard'))


class RegisterViewTest(TestCase):

    def get_valid_post(self, **kwargs):
        data = {
            'username': 'newuser',
            'email': 'new@example.com',
            'password1': 'StrongPass123!',
            'password2': 'StrongPass123!',
        }
        data.update(kwargs)
        return data

    @patch('user.views.send_registration_email_to_admin')
    @patch('user.views.send_registration_confirmation_to_user')
    def test_successful_registration(self, mock_user_email, mock_admin_email):
        response = self.client.post(reverse('register'), self.get_valid_post())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'auth/register_success.html')

    @patch('user.views.send_registration_email_to_admin')
    @patch('user.views.send_registration_confirmation_to_user')
    def test_registered_user_is_inactive(self, mock_user_email, mock_admin_email):
        self.client.post(reverse('register'), self.get_valid_post())
        user = User.objects.get(username='newuser')
        self.assertFalse(user.is_active)

    @patch('user.views.send_registration_email_to_admin')
    @patch('user.views.send_registration_confirmation_to_user')
    def test_emails_sent_on_registration(self, mock_user_email, mock_admin_email):
        self.client.post(reverse('register'), self.get_valid_post())
        self.assertTrue(mock_admin_email.called)
        self.assertTrue(mock_user_email.called)

    def test_duplicate_email_shows_error(self):
        create_user(username='existing', email='new@example.com')
        response = self.client.post(reverse('register'), self.get_valid_post())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'auth/register.html')

    def test_duplicate_username_shows_error(self):
        create_user(username='newuser', email='other@example.com')
        response = self.client.post(reverse('register'), self.get_valid_post())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'auth/register.html')

    def test_authenticated_user_redirected(self):
        user = create_user()
        self.client.force_login(user)
        response = self.client.get(reverse('register'))
        self.assertRedirects(response, reverse('dashboard'))

    def test_get_register_page(self):
        response = self.client.get(reverse('register'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'auth/register.html')


class LoginViewTest(TestCase):

    def setUp(self):
        self.user = create_user(username='loginuser', password='TestPass123!')

    def test_login_with_valid_credentials(self):
        response = self.client.post(reverse('login'), {
            'username': 'loginuser',
            'password': 'TestPass123!',
        })
        self.assertRedirects(response, reverse('dashboard'))

    def test_login_with_invalid_credentials(self):
        response = self.client.post(reverse('login'), {
            'username': 'loginuser',
            'password': 'WrongPassword!',
        })
        self.assertEqual(response.status_code, 200)
        messages = list(response.context['messages'])
        self.assertTrue(any('Invalid' in str(m) for m in messages))

    def test_inactive_user_cannot_login(self):
        inactive = create_user(username='inactive', email='i@test.com', is_active=False)
        response = self.client.post(reverse('login'), {
            'username': 'inactive',
            'password': 'TestPass123!',
        })
        self.assertEqual(response.status_code, 200)
        messages = list(response.context['messages'])
        self.assertTrue(any('review' in str(m).lower() for m in messages))

    def test_authenticated_user_redirected(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse('login'))
        self.assertRedirects(response, reverse('dashboard'))

    def test_get_login_page(self):
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'auth/login.html')

    def test_superuser_blocked_from_wadmin_if_not_super(self):
        response = self.client.post(reverse('login') + '?next=/wadmin/', {
            'username': 'loginuser',
            'password': 'TestPass123!',
            'next': '/wadmin/',
        })
        messages = list(response.wsgi_request._messages)
        self.assertTrue(any('permission' in str(m).lower() for m in messages))


class LogoutViewTest(TestCase):

    def test_logout_redirects_to_home(self):
        user = create_user()
        self.client.force_login(user)
        response = self.client.get(reverse('logout'))
        self.assertRedirects(response, reverse('home'))

    def test_user_is_logged_out(self):
        user = create_user()
        self.client.force_login(user)
        self.client.get(reverse('logout'))
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 302)  # Redirected to login


# =============================================================================
# VIEW TESTS — DASHBOARD & FILES
# =============================================================================

class DashboardViewTest(TestCase):

    def setUp(self):
        self.user = create_user()
        self.client.force_login(self.user)

    def test_dashboard_accessible_for_logged_in_user(self):
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard.html')

    def test_dashboard_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 302)

    def test_dashboard_shows_user_files(self):
        f = create_file(self.user, filename='myfile.txt')
        response = self.client.get(reverse('dashboard'))
        self.assertIn(f, response.context['files'])
        if f.file and os.path.exists(f.file.path):
            os.remove(f.file.path)

    def test_dashboard_does_not_show_other_users_files(self):
        other = create_user(username='other', email='other@test.com')
        f = create_file(other, filename='otherfile.txt')
        response = self.client.get(reverse('dashboard'))
        self.assertNotIn(f, response.context['files'])
        if f.file and os.path.exists(f.file.path):
            os.remove(f.file.path)

    def test_dashboard_shows_shared_files(self):
        owner = create_user(username='owner', email='owner@test.com')
        f = create_file(owner, filename='shared.txt')
        FileShare.objects.create(file=f, shared_with=self.user, shared_by=owner)
        response = self.client.get(reverse('dashboard'))
        self.assertIn(f, response.context['files'])
        if f.file and os.path.exists(f.file.path):
            os.remove(f.file.path)

    def test_search_filters_files(self):
        f1 = create_file(self.user, filename='alpha.txt')
        f2 = create_file(self.user, filename='beta.txt')
        response = self.client.get(reverse('dashboard') + '?q=alpha')
        files = response.context['files']
        names = [os.path.basename(f.file.name) for f in files]
        self.assertTrue(any('alpha' in n for n in names))
        for f in [f1, f2]:
            if f.file and os.path.exists(f.file.path):
                os.remove(f.file.path)

    def test_expired_files_hidden_from_dashboard(self):
        uploaded = SimpleUploadedFile('exp.txt', b'data')
        f = UserFile.objects.create(
            uploader=self.user,
            file=uploaded,
            never_expire=False,
        )
        UserFile.objects.filter(pk=f.pk).update(expires_at=timezone.now() - timedelta(seconds=10))
        f.refresh_from_db()
        response = self.client.get(reverse('dashboard'))
        self.assertNotIn(f, response.context['files'])
        if f.file and os.path.exists(f.file.path):
            os.remove(f.file.path)


class FileUploadTest(TestCase):

    def setUp(self):
        self.user = create_user()
        self.client.force_login(self.user)
        AppSettings.objects.create(max_file_size=10485760)  # 10 MB

    def tearDown(self):
        for f in UserFile.objects.all():
            if f.file and os.path.exists(f.file.path):
                os.remove(f.file.path)

    def test_file_upload_success(self):
        uploaded = SimpleUploadedFile('upload.txt', b'Hello!')
        response = self.client.post(reverse('dashboard'), {
            'file': uploaded,
            'never_expire': 'on',
        })
        self.assertRedirects(response, reverse('dashboard'))
        self.assertEqual(UserFile.objects.filter(uploader=self.user).count(), 1)

    def test_file_upload_too_large(self):
        large_content = b'x' * (11 * 1024 * 1024)  # 11 MB
        uploaded = SimpleUploadedFile('large.txt', large_content)
        response = self.client.post(reverse('dashboard'), {
            'file': uploaded,
            'never_expire': 'on',
        })
        self.assertRedirects(response, reverse('dashboard'))
        self.assertEqual(UserFile.objects.filter(uploader=self.user).count(), 0)

    def test_file_upload_with_expiry(self):
        uploaded = SimpleUploadedFile('expiring.txt', b'data')
        response = self.client.post(reverse('dashboard'), {
            'file': uploaded,
            'never_expire': '',
            'expiry_days': '1',
            'expiry_hours': '2',
            'expiry_minutes': '0',
            'expiry_seconds': '0',
        })
        self.assertRedirects(response, reverse('dashboard'))
        f = UserFile.objects.get(uploader=self.user)
        self.assertFalse(f.never_expire)
        self.assertIsNotNone(f.expires_at)

    def test_file_upload_with_sharing(self):
        other = create_user(username='other', email='other@test.com')
        uploaded = SimpleUploadedFile('shared.txt', b'data')
        response = self.client.post(reverse('dashboard'), {
            'file': uploaded,
            'never_expire': 'on',
            'shared_users': [str(other.id)],
        })
        self.assertRedirects(response, reverse('dashboard'))
        self.assertEqual(FileShare.objects.count(), 1)
        self.assertEqual(FileShare.objects.first().shared_with, other)


class FileDownloadTest(TestCase):

    def setUp(self):
        self.user = create_user()
        self.client.force_login(self.user)
        self.file = create_file(self.user, filename='download.txt', content=b'Download me')

    def tearDown(self):
        if self.file.file and os.path.exists(self.file.file.path):
            os.remove(self.file.file.path)

    def test_download_existing_file(self):
        response = self.client.get(reverse('download_file', args=[self.file.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Disposition'], f'attachment; filename="download.txt"')

    def test_download_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse('download_file', args=[self.file.id]))
        self.assertEqual(response.status_code, 302)

    def test_download_nonexistent_file_returns_404(self):
        response = self.client.get(reverse('download_file', args=[9999]))
        self.assertEqual(response.status_code, 404)


class FileDeleteTest(TestCase):

    def setUp(self):
        self.user = create_user()
        self.client.force_login(self.user)

    def test_owner_can_delete_file(self):
        f = create_file(self.user, filename='todelete.txt')
        response = self.client.post(reverse('delete_file', args=[f.id]))
        self.assertRedirects(response, reverse('dashboard'))
        self.assertEqual(UserFile.objects.filter(id=f.id).count(), 0)

    def test_other_user_cannot_delete_file(self):
        owner = create_user(username='owner2', email='owner2@test.com')
        f = create_file(owner, filename='protected.txt')
        response = self.client.post(reverse('delete_file', args=[f.id]))
        self.assertRedirects(response, reverse('dashboard'))
        self.assertEqual(UserFile.objects.filter(id=f.id).count(), 1)
        if f.file and os.path.exists(f.file.path):
            os.remove(f.file.path)

    def test_admin_can_delete_any_file(self):
        admin = create_superuser()
        self.client.force_login(admin)
        f = create_file(self.user, filename='admindelete.txt')
        response = self.client.post(reverse('delete_file', args=[f.id]))
        self.assertRedirects(response, reverse('dashboard'))
        self.assertEqual(UserFile.objects.filter(id=f.id).count(), 0)

    def test_delete_requires_login(self):
        self.client.logout()
        f = create_file(self.user, filename='loggedout.txt')
        response = self.client.post(reverse('delete_file', args=[f.id]))
        self.assertEqual(response.status_code, 302)
        if f.file and os.path.exists(f.file.path):
            os.remove(f.file.path)


class FileUpdateTest(TestCase):

    def setUp(self):
        self.user = create_user()
        self.client.force_login(self.user)
        self.file = create_file(self.user, filename='original.txt')
        AppSettings.objects.create(max_file_size=10485760)

    def tearDown(self):
        for f in UserFile.objects.all():
            if f.file and os.path.exists(f.file.path):
                os.remove(f.file.path)

    def test_update_expiry_only(self):
        response = self.client.post(reverse('dashboard'), {
            'file_id': self.file.id,
            'never_expire': '',
            'expiry_days': '3',
            'expiry_hours': '0',
            'expiry_minutes': '0',
            'expiry_seconds': '0',
        })
        self.assertRedirects(response, reverse('dashboard'))
        self.file.refresh_from_db()
        self.assertFalse(self.file.never_expire)

    def test_update_with_new_file(self):
        new_file = SimpleUploadedFile('updated.txt', b'New content')
        response = self.client.post(reverse('dashboard'), {
            'file_id': self.file.id,
            'update_file': new_file,
            'never_expire': 'on',
        })
        self.assertRedirects(response, reverse('dashboard'))

    def test_other_user_cannot_update_file(self):
        other = create_user(username='other', email='other@test.com')
        self.client.force_login(other)
        response = self.client.post(reverse('dashboard'), {
            'file_id': self.file.id,
            'never_expire': 'on',
        })
        self.assertRedirects(response, reverse('dashboard'))


# =============================================================================
# VIEW TESTS — ADMIN
# =============================================================================

class AdminDashboardTest(TestCase):

    def setUp(self):
        self.admin = create_superuser()
        self.client.force_login(self.admin)

    def test_admin_dashboard_accessible_to_superuser(self):
        response = self.client.get(reverse('custom_admin_dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_admin_dashboard_blocked_for_regular_user(self):
        user = create_user()
        self.client.force_login(user)
        response = self.client.get(reverse('custom_admin_dashboard'))
        self.assertEqual(response.status_code, 302)

    def test_admin_can_update_max_file_size(self):
        response = self.client.post(reverse('custom_admin_dashboard'), {
            'max_file_size': '5',
        })
        self.assertRedirects(response, reverse('custom_admin_dashboard'))
        settings = AppSettings.objects.first()
        self.assertEqual(settings.max_file_size, 5 * 1024 * 1024)

    def test_admin_rejects_invalid_file_size(self):
        response = self.client.post(reverse('custom_admin_dashboard'), {
            'max_file_size': 'abc',
        })
        self.assertRedirects(response, reverse('custom_admin_dashboard'))

    def test_admin_rejects_zero_file_size(self):
        response = self.client.post(reverse('custom_admin_dashboard'), {
            'max_file_size': '0',
        })
        self.assertRedirects(response, reverse('custom_admin_dashboard'))


class ToggleUserStatusTest(TestCase):

    def setUp(self):
        self.admin = create_superuser()
        self.client.force_login(self.admin)
        self.target_user = create_user(username='target', email='target@test.com')

    @patch('user.views.send_account_approved_email')
    def test_activate_user(self, mock_email):
        self.target_user.is_active = False
        self.target_user.save()
        response = self.client.get(reverse('toggle_user_status', args=[self.target_user.id]))
        self.target_user.refresh_from_db()
        self.assertTrue(self.target_user.is_active)
        self.assertTrue(mock_email.called)

    @patch('user.views.send_account_deactivated_email')
    def test_deactivate_user(self, mock_email):
        response = self.client.get(reverse('toggle_user_status', args=[self.target_user.id]))
        self.target_user.refresh_from_db()
        self.assertFalse(self.target_user.is_active)
        self.assertTrue(mock_email.called)

    def test_admin_cannot_deactivate_self(self):
        response = self.client.get(reverse('toggle_user_status', args=[self.admin.id]))
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.is_active)

    def test_regular_user_cannot_toggle(self):
        user = create_user(username='regular', email='reg@test.com')
        self.client.force_login(user)
        response = self.client.get(reverse('toggle_user_status', args=[self.target_user.id]))
        self.assertEqual(response.status_code, 302)


class DeleteUserTest(TestCase):

    def setUp(self):
        self.admin = create_superuser()
        self.client.force_login(self.admin)
        self.target_user = create_user(username='target', email='target@test.com')

    def test_admin_can_delete_user(self):
        response = self.client.post(reverse('delete_user', args=[self.target_user.id]))
        self.assertRedirects(response, reverse('custom_admin_dashboard'))
        self.assertFalse(User.objects.filter(id=self.target_user.id).exists())

    def test_admin_cannot_delete_self(self):
        response = self.client.post(reverse('delete_user', args=[self.admin.id]))
        self.assertTrue(User.objects.filter(id=self.admin.id).exists())

    def test_delete_user_also_deletes_files(self):
        f = create_file(self.target_user, filename='userfile.txt')
        file_id = f.id
        response = self.client.post(reverse('delete_user', args=[self.target_user.id]))
        self.assertFalse(UserFile.objects.filter(id=file_id).exists())

    def test_get_request_does_not_delete(self):
        response = self.client.get(reverse('delete_user', args=[self.target_user.id]))
        self.assertTrue(User.objects.filter(id=self.target_user.id).exists())

    def test_regular_user_cannot_delete_user(self):
        user = create_user(username='regular', email='reg@test.com')
        self.client.force_login(user)
        response = self.client.post(reverse('delete_user', args=[self.target_user.id]))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(User.objects.filter(id=self.target_user.id).exists())


# =============================================================================
# VIEW TESTS — PASSWORD RESET FLOW
# =============================================================================

class ForgotPasswordTest(TestCase):

    def setUp(self):
        self.user = create_user(username='resetuser', email='reset@example.com')

    def test_get_forgot_password_page(self):
        response = self.client.get(reverse('forgot_password'))
        self.assertEqual(response.status_code, 200)

    def test_authenticated_user_redirected(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse('forgot_password'))
        self.assertRedirects(response, reverse('dashboard'))

    @patch('user.views.send_password_reset_otp', return_value=True)
    def test_valid_username_sends_otp(self, mock_send):
        response = self.client.post(reverse('forgot_password'), {
            'identifier': 'resetuser'
        })
        self.assertRedirects(response, reverse('verify_otp'))
        self.assertTrue(PasswordResetOTP.objects.filter(user=self.user).exists())

    @patch('user.views.send_password_reset_otp', return_value=True)
    def test_valid_email_sends_otp(self, mock_send):
        response = self.client.post(reverse('forgot_password'), {
            'identifier': 'reset@example.com'
        })
        self.assertRedirects(response, reverse('verify_otp'))

    def test_unknown_identifier_shows_error(self):
        response = self.client.post(reverse('forgot_password'), {
            'identifier': 'nobody'
        })
        self.assertEqual(response.status_code, 200)
        messages = list(response.context['messages'])
        self.assertTrue(any('No account' in str(m) for m in messages))

    def test_empty_identifier_shows_error(self):
        response = self.client.post(reverse('forgot_password'), {
            'identifier': ''
        })
        self.assertEqual(response.status_code, 200)

    @patch('user.views.send_password_reset_otp', return_value=True)
    def test_rate_limiting_prevents_duplicate_otp(self, mock_send):
        self.client.post(reverse('forgot_password'), {'identifier': 'resetuser'})
        response = self.client.post(reverse('forgot_password'), {'identifier': 'resetuser'})
        messages = list(response.context['messages'])
        self.assertTrue(any('wait' in str(m).lower() for m in messages))

    @patch('user.views.send_password_reset_otp', return_value=False)
    def test_email_failure_shows_error(self, mock_send):
        response = self.client.post(reverse('forgot_password'), {
            'identifier': 'resetuser'
        })
        messages = list(response.context['messages'])
        self.assertTrue(any('Failed' in str(m) for m in messages))


class VerifyOTPTest(TestCase):

    def setUp(self):
        self.user = create_user(username='otpuser', email='otp@example.com')
        session = self.client.session
        session['reset_username'] = self.user.username
        session.save()
        self.otp = PasswordResetOTP.objects.create(user=self.user, otp='123456')

    def test_get_verify_otp_page(self):
        response = self.client.get(reverse('verify_otp'))
        self.assertEqual(response.status_code, 200)

    def test_no_session_redirects_to_forgot_password(self):
        self.client.session.flush()
        response = self.client.get(reverse('verify_otp'))
        self.assertRedirects(response, reverse('forgot_password'))

    def test_valid_otp_redirects_to_reset(self):
        response = self.client.post(reverse('verify_otp'), {'otp': '123456'})
        self.assertRedirects(response, reverse('reset_password'))

    def test_invalid_otp_shows_error(self):
        response = self.client.post(reverse('verify_otp'), {'otp': '000000'})
        self.assertEqual(response.status_code, 200)
        messages = list(response.context['messages'])
        self.assertTrue(any('Invalid' in str(m) for m in messages))

    def test_used_otp_rejected(self):
        self.otp.is_used = True
        self.otp.save()
        response = self.client.post(reverse('verify_otp'), {'otp': '123456'})
        self.assertEqual(response.status_code, 200)

    def test_expired_otp_redirects(self):
        self.otp.expires_at = timezone.now() - timedelta(minutes=1)
        self.otp.save()
        response = self.client.post(reverse('verify_otp'), {'otp': '123456'})
        self.assertRedirects(response, reverse('forgot_password'))

    def test_otp_marked_as_used_after_verification(self):
        self.client.post(reverse('verify_otp'), {'otp': '123456'})
        self.otp.refresh_from_db()
        self.assertTrue(self.otp.is_used)

    def test_authenticated_user_redirected(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse('verify_otp'))
        self.assertRedirects(response, reverse('dashboard'))


class ResetPasswordTest(TestCase):

    def setUp(self):
        self.user = create_user(username='pwreset', email='pw@example.com')
        self.otp = PasswordResetOTP.objects.create(
            user=self.user, otp='654321', is_used=True
        )
        session = self.client.session
        session['reset_username'] = self.user.username
        session['verified_otp_id'] = self.otp.id
        session.save()

    def test_get_reset_password_page(self):
        response = self.client.get(reverse('reset_password'))
        self.assertEqual(response.status_code, 200)

    def test_no_session_redirects_to_forgot(self):
        self.client.session.flush()
        response = self.client.get(reverse('reset_password'))
        self.assertRedirects(response, reverse('forgot_password'))

    def test_valid_password_reset(self):
        response = self.client.post(reverse('reset_password'), {
            'new_password': 'NewStrongPass123!',
            'confirm_password': 'NewStrongPass123!',
        })
        self.assertRedirects(response, reverse('login'))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('NewStrongPass123!'))

    def test_password_mismatch_shows_error(self):
        response = self.client.post(reverse('reset_password'), {
            'new_password': 'NewPass123!',
            'confirm_password': 'DifferentPass123!',
        })
        self.assertEqual(response.status_code, 200)
        messages = list(response.context['messages'])
        self.assertTrue(any('match' in str(m).lower() for m in messages))

    def test_short_password_rejected(self):
        response = self.client.post(reverse('reset_password'), {
            'new_password': 'short',
            'confirm_password': 'short',
        })
        self.assertEqual(response.status_code, 200)
        messages = list(response.context['messages'])
        self.assertTrue(any('8 characters' in str(m) for m in messages))

    def test_empty_fields_rejected(self):
        response = self.client.post(reverse('reset_password'), {
            'new_password': '',
            'confirm_password': '',
        })
        self.assertEqual(response.status_code, 200)

    def test_session_cleared_after_reset(self):
        self.client.post(reverse('reset_password'), {
            'new_password': 'NewStrongPass123!',
            'confirm_password': 'NewStrongPass123!',
        })
        self.assertNotIn('reset_username', self.client.session)
        self.assertNotIn('verified_otp_id', self.client.session)

    def test_authenticated_user_redirected(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse('reset_password'))
        self.assertRedirects(response, reverse('dashboard'))