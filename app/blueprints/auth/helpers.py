from flask import current_app, url_for
import requests
from datetime import datetime
from collections import defaultdict
from flask_login import current_user

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
    where each key maps to a dictionary mapping author usernames to a sorted
    (descending) list of report dates.
    """
    from app.models import Report, User
    # Get all reports that have an associated user.
    reports = Report.query.join(User).all()
    
    # Initialize the grouping dictionary.
    admin_grouped = {'user': {}, 'manager': {}, 'admin': {}}
    
    # Loop through each report.
    for report in reports:
        if not report.author:  # Safety check; inner join should ensure report.author exists.
            continue
        # Use the role from the report's author.
        role = report.author.role  # Expects 'user', 'manager', or 'admin'.
        author_name = report.author.username
        
        # Initialize the set for this author and role if not present.
        if author_name not in admin_grouped[role]:
            admin_grouped[role][author_name] = set()
        
        # Determine the date (preferring the EXIF datetime if available).
        taken = report.exif_datetime if report.exif_datetime else report.date_posted
        admin_grouped[role][author_name].add(taken.date())
    
    # For each role and author, sort the dates in descending order.
    for role in admin_grouped:
        for author in admin_grouped[role]:
            dates_list = sorted(list(admin_grouped[role][author]), reverse=True)
            admin_grouped[role][author] = dates_list
    
    return admin_grouped

def get_manager_reports_by_author():
    """
    For manager users: Aggregate all reports created by 'user' and 'manager'-level accounts,
    grouped by author.
    Returns a dictionary where each key is an author's username and each value is a
    sorted (descending) list of report dates.
    """
    from app.models import Report, User
    # Include both user and manager roles.
    reports = Report.query.join(User).filter(User.role.in_(['user', 'manager'])).all()
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
    from app.models import Report
    reports = Report.query.filter_by(user_id=current_user.id).all()
    
    day_counts = defaultdict(int)
    for r in reports:
        day = (r.exif_datetime if r.exif_datetime else r.date_posted).date()
        day_counts[day] += 1
    sorted_days = sorted(day_counts.keys(), reverse=True)
    default_day = sorted_days[0].strftime("%Y-%m-%d") if sorted_days else None
    return day_counts, sorted_days, default_day