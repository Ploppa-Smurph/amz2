from flask import render_template, request, redirect, url_for, flash, jsonify, Response
from sqlalchemy import func
from flask_login import login_required, current_user
from app.extensions import db
from app.models import Report, User
from app.blueprints.reports import reports_bp
from app.blueprints.reports.helpers import safe_parse_date, group_reports_by_day, paginate
import io, csv

@reports_bp.route("/daily_reports")
@login_required
def daily_reports():
    """
    Displays a preview of daily reports.
    Various query parameters (start_date, end_date, author) can be passed to filter the list.
    """
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    author = request.args.get('author')
    date_field = func.coalesce(Report.exif_datetime, Report.date_posted)
    query = Report.query

    if start_date_str:
        start_date = safe_parse_date(start_date_str)
        if start_date:
            query = query.filter(date_field >= start_date)
        else:
            flash("Invalid start date format. Use YYYY-MM-DD.", "danger")

    if end_date_str:
        end_date = safe_parse_date(end_date_str)
        if end_date:
            end_date = end_date.replace(hour=23, minute=59, second=59, microsecond=999999)
            query = query.filter(date_field <= end_date)
        else:
            flash("Invalid end date format. Use YYYY-MM-DD.", "danger")

    if author:
        query = query.join(Report.author).filter(User.username == author)

    reports_list = query.order_by(date_field.desc()).all()
    sorted_grouped = group_reports_by_day(reports_list)
    return render_template("daily_reports.html", grouped_reports=sorted_grouped)

@reports_bp.route("/daily_reports/day/<report_date>")
@login_required
def day_reports(report_date):
    """
    Displays reports for a given day in a paginated format.
    Expects report_date formatted as YYYY-MM-DD.
    """
    parsed_date = safe_parse_date(report_date)
    if not parsed_date:
        return redirect(url_for('reports.daily_reports'))

    target_date = parsed_date.date()
    reports_for_day = Report.query.filter(
        func.date(func.coalesce(Report.exif_datetime, Report.date_posted)) == target_date
    ).order_by(func.coalesce(Report.exif_datetime, Report.date_posted).desc()).all()

    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1

    page_size = 15
    paginated_reports, pagination = paginate(reports_for_day, page, page_size)
    return render_template("day_reports.html", day=target_date,
                           reports=paginated_reports, pagination=pagination)

@reports_bp.route("/api/reports", methods=["GET"])
def api_get_reports():
    """
    API endpoint that returns a JSON list of all reports.
    """
    reports_list = Report.query.all()
    response = [{
        "id": report.id,
        "title": report.title,
        "notes": report.notes,
        "date_posted": report.date_posted.isoformat() if report.date_posted else None,
        "author": report.author.username if report.author else "N/A"
    } for report in reports_list]
    return jsonify(response)

@reports_bp.route('/export_reports', methods=['GET'])
@login_required
def export_reports():
    """
    Export reports as CSV.
    This route is only available to managers and admins.
    Modify the query as needed to export reports visible to the current user.
    """
    from flask import abort
    if current_user.role not in ['admin', 'manager']:
        abort(403)

    reports_data = Report.query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Title', 'Author', 'Date Posted', 'EXIF Date/Time'])

    for report in reports_data:
        date_posted = report.date_posted.strftime('%Y-%m-%d %H:%M:%S') if report.date_posted else ''
        exif_datetime = report.exif_datetime.strftime('%Y-%m-%d %H:%M:%S') if report.exif_datetime else ''
        writer.writerow([
            report.id,
            report.title,
            report.author.username,
            date_posted,
            exif_datetime
        ])
    output.seek(0)
    return Response(output.getvalue(),
                    mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=reports.csv'})