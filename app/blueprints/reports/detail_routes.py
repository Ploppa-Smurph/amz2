from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.extensions import db
from app.models import Report, Note, Tag
from app.forms import ReportForm, NoteForm, TagForm
from app.blueprints.reports import reports_bp

@reports_bp.route("/new", methods=["GET", "POST"])
@login_required
def new_report():
    """
    Allows a logged-in user to create a new report.
    If text is entered in the 'notes' field, a note is automatically created and attached.
    Additionally, this route processes an optional tag (selected from a dropdown) for the report.
    """
    form = ReportForm()
    if form.validate_on_submit():
        image_data = None
        image_mimetype = None
        if form.image.data:
            image_data = form.image.data.read()
            image_mimetype = form.image.data.mimetype

        # Create the new report
        new_report_obj = Report(
            title=form.title.data,
            notes=form.notes.data,
            image_data=image_data,
            image_mimetype=image_mimetype,
            author=current_user
        )
        db.session.add(new_report_obj)

        # Create an initial note if any notes are provided
        if form.notes.data and form.notes.data.strip():
            initial_note = Note(
                content=form.notes.data,
                report=new_report_obj,
                user_id=current_user.id
            )
            db.session.add(initial_note)

        # --- New: Process the Tag value from the dropdown ---
        # The new_reports.html page includes a dropdown with name="tags"
        selected_tag_name = request.form.get('tags', '').strip()
        if selected_tag_name:
            # Check if the tag already exists. Create it if not.
            tag = Tag.query.filter_by(name=selected_tag_name).first()
            if not tag:
                tag = Tag(name=selected_tag_name)
                db.session.add(tag)
            # Associate the tag with the report.
            new_report_obj.tags.append(tag)
        # ------------------------------------------------------

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

@reports_bp.route('/report/<int:report_id>/add_tag', methods=['POST'])
@login_required
def add_tag(report_id):
    """Add a new tag to the specified report."""
    report = Report.query.get_or_404(report_id)
    # Retrieve the selected tag value from the form. The select element 
    # in report_notes.html has the name 'tag'
    selected_tag = request.form.get('tag', '').strip()
    
    if selected_tag:
        # Look for the tag in the database; if it doesn't exist, create it.
        tag = Tag.query.filter_by(name=selected_tag).first()
        if not tag:
            tag = Tag(name=selected_tag)
            db.session.add(tag)
        # Add the tag to the report if it's not already associated
        if tag not in report.tags:
            report.tags.append(tag)
            try:
                db.session.commit()
                flash("Tag added successfully!", "success")
            except Exception as e:
                db.session.rollback()
                flash("Error adding tag: " + str(e), "danger")
        else:
            flash("This tag is already associated with the report.", "info")
    else:
        flash("No tag selected.", "warning")
        
    # Redirect back to the report notes page
    return redirect(url_for('reports.report_notes', report_id=report.id))

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
    tag_form = TagForm()  # Instantiate the tag form for CSRF protection and tag selection.
    
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
    
    top_notes = Note.query.filter_by(report_id=report.id, parent_id=None)\
                           .order_by(Note.timestamp.asc()).all()
    return render_template('report_notes.html',
                           report=report,
                           form=form,
                           tag_form=tag_form,
                           notes=top_notes)