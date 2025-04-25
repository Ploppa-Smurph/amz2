from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.extensions import db
from app.models import Report, Note
from app.forms import ReportForm, NoteForm
from app.blueprints.reports import reports_bp

@reports_bp.route("/new", methods=["GET", "POST"])
@login_required
def new_report():
    """
    Allows a logged-in user to create a new report.
    If text is entered in the 'notes' field, a note is automatically created and attached.
    """
    form = ReportForm()
    if form.validate_on_submit():
        image_data = None
        image_mimetype = None
        if form.image.data:
            image_data = form.image.data.read()
            image_mimetype = form.image.data.mimetype

        new_report_obj = Report(
            title=form.title.data,
            notes=form.notes.data,
            image_data=image_data,
            image_mimetype=image_mimetype,
            author=current_user
        )
        db.session.add(new_report_obj)

        if form.notes.data and form.notes.data.strip():
            # Import Note from app.models (already available via __init__.py)
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

@reports_bp.route('/report/<int:report_id>', methods=["GET", "POST"])
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

@reports_bp.route('/report/<int:report_id>/notes', methods=['GET', 'POST'])
@login_required
def report_notes(report_id):
    """
    Displays all notes attached to a given report and allows posting a note or reply.
    Permission rules:
      - Users can comment if they are the report author or the report was submitted by a non-admin.
      - Managers can view and comment on all user and manager reports.
      - Admins can view and comment on all reports.
    """
    report = Report.query.get_or_404(report_id)
    
    if current_user.role == 'user':
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
    
    top_notes = Note.query.filter_by(report_id=report.id, parent_id=None).order_by(Note.timestamp.asc()).all()
    return render_template('report_notes.html', report=report, form=form, notes=top_notes)