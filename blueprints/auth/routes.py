# blueprints/auth/routes.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from forms import RegistrationForm, LoginForm, ResetPasswordRequestForm, ResetPasswordForm
from models import User
from extensions import db
from flask_login import login_user, logout_user, current_user
import requests

try:
    from werkzeug.urls import url_parse
except ImportError:
    try:
        from werkzeug.http import parse_url as url_parse
    except ImportError:
        from urllib.parse import urlparse as url_parse

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('register.html', title='Register', form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    # Default to not showing the extra links
    show_forgot = False
    show_register = False
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Login unsuccessful. Please check your username and password.', 'danger')
            # Set flags so that in your template the extra buttons are shown
            show_forgot = True
            show_register = True
        else:
            login_user(user)
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('home')
            return redirect(next_page)
    return render_template('login.html', title='Login', form=form,
                           show_forgot=show_forgot, show_register=show_register)

@auth_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@auth_bp.route('/profile')
def profile():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    return render_template('profile.html', user=current_user)

# ------------------------------------
# NEW: Password Reset Endpoints
# ------------------------------------

@auth_bp.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.get_reset_token()  # Method defined in models.py (see additional changes below)
            send_reset_email(user, token)   # Sends email via Mailgun
        flash('If an account with that email exists, instructions to reset your password have been sent.', 'info')
        return redirect(url_for('auth.login'))
    return render_template('reset_password_request.html', title='Reset Password', form=form)

@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)   # Method defined in models.py (see additional changes below)
    if not user:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('auth.reset_password_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('reset_password.html', title='Reset Password', form=form)

def send_reset_email(user, token):
    """
    Sends a password reset email to the user using Mailgun.
    Ensure that your app config contains MAILGUN_DOMAIN, MAILGUN_API_KEY,
    and optionally MAIL_DEFAULT_SENDER.
    """
    reset_url = url_for('auth.reset_password', token=token, _external=True)
    subject = "Password Reset Request"
    text = f"""Hi {user.username},

To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email.
"""
    # Retrieve Mailgun configuration from your app's config
    MAILGUN_DOMAIN = current_app.config.get('MAILGUN_DOMAIN')
    MAILGUN_API_KEY = current_app.config.get('MAILGUN_API_KEY')
    sender = current_app.config.get('MAIL_DEFAULT_SENDER') or f"no-reply@{MAILGUN_DOMAIN}"
    
    response = requests.post(
        f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
        auth=("api", MAILGUN_API_KEY),
        data={"from": sender,
              "to": [user.email],
              "subject": subject,
              "text": text})
    
    if response.status_code != 200:
        current_app.logger.error(f"Failed to send password reset email: {response.text}")
    return response