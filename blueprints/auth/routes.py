# auth/routes.py

from flask import (
    Blueprint, render_template, redirect, url_for, flash,
    request, current_app, session
)
from forms import (
    RegistrationForm, LoginForm, ResetPasswordRequestForm,
    ResetPasswordForm, FirstTimePasswordChangeForm
)
from admin_forms import RoleChangeForm, AdminCreateUserForm  # Admin-only forms
from models import User
from extensions import db
from flask_login import (
    login_user, logout_user, current_user, login_required
)
import requests
try:
    from werkzeug.urls import url_parse
except ImportError:
    from urllib.parse import urlparse as url_parse
from datetime import datetime
from collections import defaultdict

auth_bp = Blueprint('auth', __name__)
# -----------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------
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
    MAILGUN_DOMAIN = current_app.config.get('MAILGUN_DOMAIN')
    MAILGUN_API_KEY = current_app.config.get('MAILGUN_API_KEY')
    sender = current_app.config.get('MAIL_DEFAULT_SENDER') or f"no-reply@{MAILGUN_DOMAIN}"
    
    response = requests.post(
        f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
        auth=("api", MAILGUN_API_KEY),
        data={
            "from": sender,
            "to": [user.email],
            "subject": subject,
            "text": text
        }
    )
    if response.status_code != 200:
        current_app.logger.error(f"Failed to send password reset email: {response.text}")
    return response


def admin_required():
    """Helper: Check if the current user is an admin."""
    return current_user.is_authenticated and current_user.role == 'admin'


def get_admin_grouped_reports():
    """
    For admin users: Aggregate all reports by role and then by author.
    Returns a dictionary with keys: 'user', 'manager', 'admin'
    where each key maps to a dictionary that maps author usernames to a sorted
    (descending) list of report dates.
    """
    from models import Report, User
    reports = Report.query.join(User).all()
    admin_grouped = {'user': {}, 'manager': {}, 'admin': {}}
    for report in reports:
        if not report.author:
            continue
        role = report.author.role  # 'user', 'manager', or 'admin'
        author_name = report.author.username
        if author_name not in admin_grouped[role]:
            admin_grouped[role][author_name] = set()
        taken = report.exif_datetime if report.exif_datetime else report.date_posted
        admin_grouped[role][author_name].add(taken.date())
    # Convert sets to sorted (descending) lists.
    for role in admin_grouped:
        for author in admin_grouped[role]:
            dates_list = sorted(list(admin_grouped[role][author]), reverse=True)
            admin_grouped[role][author] = dates_list
    return admin_grouped


def get_manager_reports_by_author():
    """
    For manager users: Aggregate all reports created by 'user'-level accounts,
    grouped by author.
    Returns a dictionary where each key is an author's username and each value is a
    sorted (descending) list of the dates on which that author created a report.
    """
    from models import Report, User
    reports = Report.query.join(User).filter(User.role == 'user').all()
    reports_by_author = {}
    for r in reports:
        if not r.author:
            continue
        author = r.author.username
        date = (r.exif_datetime if r.exif_datetime else r.date_posted).date()
        reports_by_author.setdefault(author, set()).add(date)
    for author in reports_by_author:
        reports_by_author[author] = sorted(list(reports_by_author[author]), reverse=True)
    return reports_by_author


def get_user_day_counts():
    """
    For regular (non-admin, non-manager) users: Group the current user's reports by day.
    Returns a tuple: (day_counts, sorted_days, default_day)
    """
    from models import Report
    if current_user.role == "user":
        reports = Report.query.filter_by(user_id=current_user.id).all()
    elif current_user.role == "manager":
        reports = Report.query.filter_by(user_id=current_user.id).all()
    else:
        reports = Report.query.filter_by(user_id=current_user.id).all()
    
    day_counts = defaultdict(int)
    for r in reports:
        day = (r.exif_datetime if r.exif_datetime else r.date_posted).date()
        day_counts[day] += 1
    sorted_days = sorted(day_counts.keys(), reverse=True)
    default_day = sorted_days[0].strftime("%Y-%m-%d") if sorted_days else None
    return day_counts, sorted_days, default_day


# -----------------------------------------------------------------------
# Profile View
# -----------------------------------------------------------------------
@auth_bp.route('/profile', endpoint='profile_page')
@login_required
def profile():
    from models import Report, User
    if current_user.role == "admin":
        admin_grouped = get_admin_grouped_reports()
        return render_template('profile.html', user=current_user, admin_grouped_reports=admin_grouped)
    elif current_user.role == "manager":
        reports_by_author = get_manager_reports_by_author()
        return render_template('profile.html', user=current_user, reports_by_author=reports_by_author)
    else:
        day_counts, sorted_days, default_day = get_user_day_counts()
        return render_template('profile.html', user=current_user, day_counts=day_counts,
                               sorted_days=sorted_days, default_day=default_day)

# -----------------------------------------------------------------------
# Public Routes: Registration, Login, Logout, Profile, Password Reset
# -----------------------------------------------------------------------
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        # Force role to "user" for public registrations.
        user.role = 'user'
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
    show_forgot = False
    show_register = False
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Login unsuccessful. Please check your username and password.', 'danger')
            show_forgot = True
            show_register = True
        else:
            login_user(user)
            session['server_run_id'] = current_app.config['SERVER_RUN_ID']
            if user.must_change_password:
                return redirect(url_for('auth.force_change_password'))
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('auth.profile')
            flash('Login successful!', 'success')
            return redirect(next_page)
    return render_template('login.html', title='Login', form=form,
                           show_forgot=show_forgot, show_register=show_register)


@auth_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@auth_bp.route('/profile')
@login_required
def profile():
    from models import Report, User
    if current_user.role == "admin":
        admin_grouped = get_admin_grouped_reports()
        return render_template('profile.html', user=current_user, admin_grouped_reports=admin_grouped)
    else:
        day_counts, sorted_days, default_day = get_user_day_counts()
        return render_template('profile.html', user=current_user, day_counts=day_counts,
                               sorted_days=sorted_days, default_day=default_day)


@auth_bp.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.get_reset_token()  # Defined in models.py
            send_reset_email(user, token)
        flash('If an account with that email exists, instructions to reset your password have been sent.', 'info')
        return redirect(url_for('auth.login'))
    return render_template('reset_password_request.html', title='Reset Password', form=form)


@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
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


@auth_bp.route('/force_change_password', methods=['GET', 'POST'])
@login_required
def force_change_password():
    # Only require password change if the flag is set.
    if not current_user.must_change_password:
        return redirect(url_for('home'))
    form = FirstTimePasswordChangeForm()
    if form.validate_on_submit():
        current_user.set_password(form.new_password.data)
        current_user.must_change_password = False
        db.session.commit()
        flash("Your password has been updated.", "success")
        return redirect(url_for('auth.profile'))
    return render_template('force_change_password.html', title="Change Password", form=form)

# -----------------------------------------------------------------------
# Admin Endpoints
# -----------------------------------------------------------------------
@auth_bp.route('/admin/change_role/<int:user_id>', methods=['GET', 'POST'])
@login_required
def change_role(user_id):
    if not admin_required():
        flash("You do not have permission to update roles.", "danger")
        return redirect(url_for('home'))
    user_to_update = User.query.get_or_404(user_id)
    form = RoleChangeForm()
    if form.validate_on_submit():
        # Verify current admin password for security.
        if not current_user.check_password(form.current_password.data):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for('auth.change_role', user_id=user_id))
        user_to_update.role = form.role.data
        db.session.commit()
        flash(f"Updated role for user {user_to_update.username} to {form.role.data}.", "success")
        return redirect(url_for('auth.user_list'))
    form.role.data = user_to_update.role
    return render_template('admin/change_role.html', user=user_to_update, form=form)


@auth_bp.route('/admin/user_list')
@login_required
def user_list():
    if not admin_required():
        flash("You do not have permission to view this page.", "danger")
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin/user_list.html', users=users)


@auth_bp.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if not admin_required():
        flash("You do not have permission to create users.", "danger")
        return redirect(url_for('home'))
    form = AdminCreateUserForm()
    if form.validate_on_submit():
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data  # Now can be "user", "manager", or "admin"
        )
        new_user.set_password(form.temp_password.data)
        new_user.must_change_password = True  # Force the new user to change their password
        db.session.add(new_user)
        db.session.commit()
        flash("User created. They will be required to set a new password on first login.", "success")
        return redirect(url_for('auth.user_list'))
    return render_template('admin/create_user.html', form=form)

