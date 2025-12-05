from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags


def send_registration_email_to_admin(user):
    """Send email to admin when new user registers"""
    subject = f'New User Registration - {user.username}'
    
    html_message = f"""
    <html>
        <body>
            <h2>New User Registration</h2>
            <p>A new user has registered and is waiting for approval.</p>
            <ul>
                <li><strong>Username:</strong> {user.username}</li>
                <li><strong>Email:</strong> {user.email}</li>
                <li><strong>First Name:</strong> {user.first_name or 'N/A'}</li>
                <li><strong>Last Name:</strong> {user.last_name or 'N/A'}</li>
            </ul>
            <p>Please log in to the admin panel to approve or reject this user.</p>
            <p><a href="{settings.SITE_URL}/wadmin/" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Go to Admin Panel</a></p>
        </body>
    </html>
    """
    
    plain_message = strip_tags(html_message)
    
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[settings.ADMIN_EMAIL],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error sending email to admin: {str(e)}")
        return False


def send_registration_confirmation_to_user(user):
    """Send confirmation email to user after registration"""
    subject = 'Registration Successful - Waiting for Admin Approval'
    
    html_message = f"""
    <html>
        <body>
            <h2>Welcome to IntraShare, {user.username}!</h2>
            <p>Thank you for registering. Your account has been created successfully.</p>
            <p>Your account is currently <strong>under admin review</strong> and will be activated once approved by our administrator.</p>
            <p>You will receive another email once your account is approved.</p>
            <br>
            <p>If you have any questions, please contact the administrator.</p>
            <p>Best regards,<br>IntraShare Team</p>
        </body>
    </html>
    """
    
    plain_message = strip_tags(html_message)
    
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error sending email to user: {str(e)}")
        return False


def send_account_approved_email(user):
    """Send email to user when their account is approved"""
    subject = 'Account Approved - Welcome to IntraShare!'
    
    html_message = f"""
    <html>
        <body>
            <h2>Great News, {user.username}!</h2>
            <p>Your account has been <strong>approved by the administrator</strong>.</p>
            <p>You can now log in and start using IntraShare.</p>
            <p><a href="{settings.SITE_URL}/login/" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Login Now</a></p>
            <br>
            <p>If you have any questions, feel free to contact us.</p>
            <p>Best regards,<br>IntraShare Team</p>
        </body>
    </html>
    """
    
    plain_message = strip_tags(html_message)
    
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error sending approval email: {str(e)}")
        return False


def send_account_deactivated_email(user):
    """Send email to user when their account is deactivated"""
    subject = 'Account Deactivated - IntraShare'
    
    html_message = f"""
    <html>
        <body>
            <h2>Account Status Update</h2>
            <p>Dear {user.username},</p>
            <p>Your account has been <strong>deactivated</strong> by the administrator.</p>
            <p>If you believe this is a mistake or have questions, please contact the administrator.</p>
            <br>
            <p>Best regards,<br>IntraShare Team</p>
        </body>
    </html>
    """
    
    plain_message = strip_tags(html_message)
    
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error sending deactivation email: {str(e)}")
        return False