from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from forms import ReportForm
from models import Report, User
from extensions import db
from flask_login import current_user, login_required
from sqlalchemy import func

reports_bp = Blueprint("reports", __name__)

@reports_bp.route("/daily_reports")
@login_required
def daily_reports():
    # Get filtering criteria from the query parameters.
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    author = request.args.get('author')
    
    # Use the EXIF datetime if available; otherwise fall back to the default posting date.
    date_field = func.coalesce(Report.exif_datetime, Report.date_posted)
    
    query = Report.query

    # Apply start date filter if provided.
    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            query = query.filter(date_field >= start_date)
        except ValueError:
            flash("Invalid start date format. Use YYYY-MM-DD.", "danger")
    # Apply end date filter if provided.
    if end_date_str:
        try:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
            end_date = end_date.replace(hour=23, minute=59, second=59, microsecond=999999)
            query = query.filter(date_field <= end_date)
        except ValueError:
            flash("Invalid end date format. Use YYYY-MM-DD.", "danger")
    # Apply author filter if provided.
    if author:
        query = query.join(Report.author).filter(User.username == author)
    
    # Order the reports by the taken date (EXIF or posting date if EXIF is missing)
    reports = query.order_by(date_field.desc()).all()
    
    # Group reports by day (using the taken datetime)
    grouped_reports = {}
    for report in reports:
        taken = report.exif_datetime if report.exif_datetime else report.date_posted
        day = taken.date()
        grouped_reports.setdefault(day, []).append(report)
    sorted_grouped = dict(sorted(grouped_reports.items(), key=lambda item: item[0], reverse=True))
    
    return render_template("daily_reports.html", grouped_reports=sorted_grouped)

@reports_bp.route("/daily_reports/day/<report_date>")
@login_required
def day_reports(report_date):
    try:
        target_date = datetime.strptime(report_date, '%Y-%m-%d').date()
    except ValueError:
        return redirect(url_for('reports.daily_reports'))
    
    # Filter reports for the specified day using the taken date.
    reports_for_day = Report.query.filter(
        func.date(func.coalesce(Report.exif_datetime, Report.date_posted)) == target_date
    ).order_by(func.coalesce(Report.exif_datetime, Report.date_posted).desc()).all()
    
    # Simple pagination (15 per page):
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

@reports_bp.route("/new", methods=["GET", "POST"])
@login_required
def new_report():
    form = ReportForm()
    if form.validate_on_submit():
        # Expecting ReportForm to have an additional s3_key field.
        s3_key = form.s3_key.data.strip() if hasattr(form, 's3_key') and form.s3_key.data else None
        exif_dt = None
        if s3_key:
            from amazon_utils import get_exif_datetime
            exif_dt = get_exif_datetime(s3_key)
        report = Report(
            title=form.title.data,
            content=form.content.data,
            s3_key=s3_key,
            exif_datetime=exif_dt,
            author=current_user
        )
        db.session.add(report)
        db.session.commit()
        flash('Your report has been posted!', 'success')
        return redirect(url_for('reports.daily_reports'))
    return render_template("new_report.html", title="New Report", form=form)