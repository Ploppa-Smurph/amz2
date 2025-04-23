# blueprints/reports/routes.py
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import func
from flask_login import login_required, current_user
from extensions import db
from models import User, Report, Tag
from forms import ReportForm

# Create the blueprint; here we name it "reports"
reports = Blueprint("reports", __name__)

@reports.route("/daily_reports")
@login_required
def daily_reports():
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    author = request.args.get('author')
    date_field = func.coalesce(Report.exif_datetime, Report.date_posted)
    query = Report.query

    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            query = query.filter(date_field >= start_date)
        except ValueError:
            flash("Invalid start date format. Use YYYY-MM-DD.", "danger")
    if end_date_str:
        try:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
            end_date = end_date.replace(hour=23, minute=59, second=59, microsecond=999999)
            query = query.filter(date_field <= end_date)
        except ValueError:
            flash("Invalid end date format. Use YYYY-MM-DD.", "danger")
    if author:
        query = query.join(Report.author).filter(User.username == author)

    reports_list = query.order_by(date_field.desc()).all()
    grouped_reports = {}
    for report in reports_list:
        taken = report.exif_datetime if report.exif_datetime else report.date_posted
        day = taken.date()
        grouped_reports.setdefault(day, []).append(report)

    sorted_grouped = dict(sorted(grouped_reports.items(), key=lambda item: item[0], reverse=True))
    return render_template("daily_reports.html", grouped_reports=sorted_grouped)

@reports.route("/daily_reports/day/<report_date>")
@login_required
def day_reports(report_date):
    try:
        target_date = datetime.strptime(report_date, '%Y-%m-%d').date()
    except ValueError:
        return redirect(url_for('reports.daily_reports'))
    
    reports_for_day = Report.query.filter(
        func.date(func.coalesce(Report.exif_datetime, Report.date_posted)) == target_date
    ).order_by(func.coalesce(Report.exif_datetime, Report.date_posted).desc()).all()
    
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1
    page_size = 15
    total_count = len(reports_for_day)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated_reports = reports_for_day[start_idx:end_idx]
    total_pages = (total_count + page_size - 1) // page_size
    
    pagination = {
        "current_page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "total_count": total_count
    }
    return render_template("day_reports.html", day=target_date, reports=paginated_reports, pagination=pagination)

@reports.route("/api/reports", methods=["GET"])
def api_get_reports():
    reports_list = Report.query.all()
    response = [{
        "id": report.id,
        "title": report.title,
        "notes": report.notes,
        "date_posted": report.date_posted.isoformat() if report.date_posted else None,
        "author": report.author.username if report.author else "N/A"
    } for report in reports_list]
    return jsonify(response)

@reports.route("/new", methods=["GET", "POST"])
@login_required
def new_report():
    form = ReportForm()
    if form.validate_on_submit():
        image_data = None
        image_mimetype = None
        if form.image.data:
            image_data = form.image.data.read()
            image_mimetype = form.image.data.mimetype
        new_report = Report(
            title=form.title.data,
            notes=form.notes.data,
            image_data=image_data,
            image_mimetype=image_mimetype,
            author=current_user
        )
        db.session.add(new_report)
        db.session.commit()
        flash("Your report has been posted!", "success")
        return redirect(url_for("reports.daily_reports"))
    return render_template("new_report.html", title="New Report", form=form)

@reports.route('/report/<int:report_id>')
@login_required
def view_report(report_id):
    report = Report.query.get_or_404(report_id)
    return render_template("report_detail.html", report=report)

@reports.route('/all_manager_reports')
@login_required
def all_manager_reports():
    # Ensure only admins can access this route
    if current_user.role != 'admin':
        flash("You do not have permission to view this page.", "danger")
        return redirect(url_for('home'))
    # Add logic to retrieve manager reports
    manager_reports = Report.query.join(User).filter(User.role == 'manager').all()
    return render_template('all_manager_reports.html', reports=manager_reports)

@reports.route('/all_user_reports')
@login_required
def all_user_reports():
    # Ensure only admins and managers can access this route; customize as needed.
    if current_user.role not in ['admin', 'manager']:
        flash("You do not have permission to view this page.", "danger")
        return redirect(url_for('home'))
    # Add logic to retrieve user reports
    user_reports = Report.query.join(User).filter(User.role == 'user').all()
    return render_template('all_user_reports.html', reports=user_reports)