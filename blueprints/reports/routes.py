# blueprints/reports/routes.py

from datetime import datetime
from flask import (
    Blueprint, render_template, Response, request,
    redirect, url_for, flash, jsonify
)
from sqlalchemy import func
from flask_login import login_required, current_user
from extensions import db
from models import User, Report, Tag, Note
from forms import ReportForm, NoteForm
import io, csv

reports = Blueprint("reports", __name__)

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
def safe_parse_date(date_str, fmt='%Y-%m-%d'):
    """
    Attempt to parse a date string with the given format.
    Return the parsed datetime object on success, or None on failure.
    """
    try:
        return datetime.strptime(date_str, fmt)
    except (ValueError, TypeError):
        return None

def group_reports_by_day(reports_list):
    """
    Groups a list of Report objects by the date component of their
    exif_datetime (if present) or date_posted.
    Returns a dict with date keys sorted in descending order.
    """
    grouped = {}
    for report in reports_list:
        taken = report.exif_datetime if report.exif_datetime else report.date_posted
        day = taken.date()
        grouped.setdefault(day, []).append(report)
    # Sort by day (most recent first)
    return dict(sorted(grouped.items(), key=lambda item: item[0], reverse=True))

def paginate(items, page, page_size):
    """
    Returns a slice of items for the given page number and page size,
    along with a pagination dictionary.
    """
    total_count = len(items)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated = items[start_idx:end_idx]
    total_pages = (total_count + page_size - 1) // page_size
    pagination = {
        "current_page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "total_count": total_count
    }
    return paginated, pagination

# -----------------------------------------------------------------------------
# Report Listing Routes
# -----------------------------------------------------------------------------
@reports.route("/daily_reports")
@login_required
def daily_reports():
    """
    Displays a preview of daily reports.
    Various query parameters (start_date, end_date, author) can be passed
    to filter the list.
    """
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    author = request.args.get('author')
    # Use COALESCE: if exif_datetime is not null, then exponentiate that; if null, use date_posted.
    date_field = func.coalesce(Report.exif_datetime, Report.date_posted)
    query = Report.query

    # Filter by start_date if present.
    if start_date_str:
        start_date = safe_parse_date(start_date_str)
        if start_date:
            query = query.filter(date_field >= start_date)
        else:
            flash("Invalid start date format. Use YYYY-MM-DD.", "danger")

    # Filter by end_date if present.
    if end_date_str:
        end_date = safe_parse_date(end_date_str)
        if end_date:
            end_date = end_date.replace(hour=23, minute=59, second=59, microsecond=999999)
            query = query.filter(date_field <= end_date)
        else:
            flash("Invalid end date format. Use YYYY-MM-DD.", "danger")

    # Filter by author if provided.
    if author:
        query = query.join(Report.author).filter(User.username == author)

    # Retrieve and group the reports by day.
    reports_list = query.order_by(date_field.desc()).all()
    sorted_grouped = group_reports_by_day(reports_list)
    return render_template("daily_reports.html", grouped_reports=sorted_grouped)

@reports.route("/daily_reports/day/<report_date>")
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

@reports.route("/api/reports", methods=["GET"])
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

@reports.route('/export_reports', methods=['GET'])
@login_required
def export_reports():
    """
    Export reports as CSV.
    This route is only available to managers and admins.
    Modify the query as needed to export reports visible to the current user.
    """
    # Only allow admins and managers to export
    if current_user.role not in ['admin', 'manager']:
        abort(403)

    # Example: query all reports (adjust as necessary)
    reports_data = Report.query.all()

    # Create an in-memory output file for csv.writer
    output = io.StringIO()
    writer = csv.writer(output)

    # Write CSV header row (customize column names as needed)
    writer.writerow(['ID', 'Title', 'Author', 'Date Posted', 'EXIF Date/Time'])

    # Write data rows
    for report in reports_data:
        # Format dates; if no EXIF datetime exists, leave it blank.
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
    
    # Return the CSV as a downloadable file attachment
    return Response(output.getvalue(), 
                    mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=reports.csv'})

# -----------------------------------------------------------------------------
# Report Creation & Detail Routes
# -----------------------------------------------------------------------------
@reports.route("/new", methods=["GET", "POST"])
@login_required
def new_report():
    """
    Allows a logged-in user to create a new report.
    If a user enters text in the 'notes' field, a note is automatically
    created and attached to the report.
    """
    form = ReportForm()
    if form.validate_on_submit():
        image_data = None
        image_mimetype = None
        if form.image.data:
            image_data = form.image.data.read()
            image_mimetype = form.image.data.mimetype

        # Create the report; note that we store the submitted notes in Report.notes
        new_report_obj = Report(
            title=form.title.data,
            notes=form.notes.data,   # value remains stored if you wish to use elsewhere
            image_data=image_data,
            image_mimetype=image_mimetype,
            author=current_user
        )
        db.session.add(new_report_obj)
        
        # If the report's form includes notes text, also create a threaded note.
        if form.notes.data and form.notes.data.strip():
            from models import Note  # Ensure Note is imported
            initial_note = Note(
                content=form.notes.data,
                report=new_report_obj,
                user_id=current_user.id
            )
            db.session.add(initial_note)
        
        try:
            db.session.commit()
            flash("Your report has been posted!", "success")
        except Exception as e:
            db.session.rollback()
            flash("There was an error posting your report: " + str(e), "danger")
            return redirect(url_for("reports.new_report"))
        return redirect(url_for("reports.daily_reports"))
    else:
        if request.method == "POST":
            flash("Form did not validate: " + str(form.errors), "danger")
    return render_template("new_report.html", title="New Report", form=form)

@reports.route('/report/<int:report_id>', methods=["GET", "POST"])
@login_required
def view_report(report_id):
    report = Report.query.get_or_404(report_id)
    form = NoteForm()
    if form.validate_on_submit():
        parent_id = request.form.get('parent_id')
        new_note = Note(
            content=form.content.data,
            report=report,
            user_id=current_user.id,
            parent_id=int(parent_id) if parent_id and parent_id.isdigit() else None
        )
        db.session.add(new_note)
        try:
            db.session.commit()
            flash("Your note was posted.", "success")
        except Exception as e:
            db.session.rollback()
            flash("Error posting your note: " + str(e), "danger")
        return redirect(url_for('reports.view_report', report_id=report.id))
    return render_template("report_detail.html", report=report, form=form)

@reports.route('/report/<int:report_id>/notes', methods=['GET', 'POST'])
@login_required
def report_notes(report_id):
    """
    Displays all notes attached to a given report and allows posting a note
    or reply.
    
    Permission rules:
      - Users (role "user") can comment on a report if they are the author
         or if the report was submitted by a non-admin (e.g. their manager or peer).
      - Managers can view and comment on all user and manager reports.
      - Admins can view and comment on all reports.
    """
    report = Report.query.get_or_404(report_id)
    
    # Permission check:
    if current_user.role == 'user':
        # Allow if the report is authored by the current user or if
        # the report is not authored by an admin (i.e. it should be their manager or a peer's).
        if report.author != current_user and report.author.role == 'admin':
            flash("You do not have permission to view or post notes on an admin report.", "danger")
            return redirect(url_for('reports.daily_reports'))
    
    form = NoteForm()
    if form.validate_on_submit():
        parent_id = request.form.get('parent_id')
        new_note = Note(
            content=form.content.data,
            report=report,
            user_id=current_user.id,
            parent_id=int(parent_id) if parent_id and parent_id.isdigit() else None
        )
        db.session.add(new_note)
        try:
            db.session.commit()
            flash("Your note was posted successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash("Error posting note: " + str(e), "danger")
        return redirect(url_for('reports.report_notes', report_id=report.id))
    
    # Retrieve top-level notes (without a parent)
    top_notes = Note.query.filter_by(report_id=report.id, parent_id=None).order_by(Note.timestamp.asc()).all()
    return render_template('report_notes.html', report=report, form=form, notes=top_notes)

# -----------------------------------------------------------------------------
# Admin Filtered Report Routes
# -----------------------------------------------------------------------------
@reports.route('/all_manager_reports')
@login_required
def all_manager_reports():
    """
    For admins only: Displays a list of reports created by manager users.
    """
    if current_user.role != 'admin':
        flash("You do not have permission to view this page.", "danger")
        return redirect(url_for('home'))
    manager_reports = Report.query.join(User).filter(User.role == 'manager').all()
    return render_template('all_manager_reports.html', reports=manager_reports)

@reports.route('/all_user_reports')
@login_required
def all_user_reports():
    """
    For admins and managers: Displays a list of reports created by user-level users.
    """
    if current_user.role not in ['admin', 'manager']:
        flash("You do not have permission to view this page.", "danger")
        return redirect(url_for('home'))
    user_reports = Report.query.join(User).filter(User.role == 'user').all()
    return render_template('all_user_reports.html', reports=user_reports)