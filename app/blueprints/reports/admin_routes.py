from flask import render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models import Report, User
from app.blueprints.reports import reports_bp

@reports_bp.route('/all_manager_reports')
@login_required
def all_manager_reports():
    """
    For admins only: Displays a list of reports created by manager users.
    """
    if current_user.role != 'admin':
        flash("You do not have permission to view this page.", "danger")
        return redirect(url_for('home'))
    manager_reports = Report.query.join(Report.author).filter(User.role == 'manager').all()
    return render_template('all_manager_reports.html', reports=manager_reports)

@reports_bp.route('/all_user_reports')
@login_required
def all_user_reports():
    """
    For admins and managers: Displays a list of reports created by user-level users.
    """
    if current_user.role not in ['admin', 'manager']:
        flash("You do not have permission to view this page.", "danger")
        return redirect(url_for('home'))
    user_reports = Report.query.join(Report.author).filter(User.role == 'user').all()
    return render_template('all_user_reports.html', reports=user_reports)