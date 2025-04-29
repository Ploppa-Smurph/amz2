# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
from flask_wtf.file import FileField, FileAllowed
from app.models import User

# Registration form with filters to strip whitespace
class RegistrationForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired(), Length(min=2, max=20)],
        filters=[lambda x: x.strip() if x else None]
    )
    email = StringField(
        'Email',
        validators=[DataRequired(), Email()],
        filters=[lambda x: x.strip() if x else None]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(), Length(min=6)]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('password')]
    )
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already in use.')

# Login form with whitespace filtering
class LoginForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired(), Length(min=2, max=20)],
        filters=[lambda x: x.strip() if x else None]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired()]
    )
    submit = SubmitField('Login')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField(
        'Email',
        validators=[DataRequired(), Email()],
        filters=[lambda x: x.strip() if x else None]
    )
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        'New Password',
        validators=[DataRequired(), Length(min=6)]
    )
    confirm_password = PasswordField(
        'Confirm New Password',
        validators=[DataRequired(), EqualTo('password')]
    )
    submit = SubmitField('Reset Password')

# Form for forcing a password change on the first admin/user login.
class FirstTimePasswordChangeForm(FlaskForm):
    new_password = PasswordField(
        "New Password",
        validators=[DataRequired(), Length(min=6)],
        render_kw={"placeholder": "Enter new password"}
    )
    confirm_new_password = PasswordField(
        "Confirm New Password",
        validators=[DataRequired(), EqualTo('new_password')],
        render_kw={"placeholder": "Confirm new password"}
    )
    submit = SubmitField("Change Password")

class ReportForm(FlaskForm):
    title = StringField(
        'Title',
        validators=[Optional(), Length(max=100)],
        render_kw={"placeholder": "Enter a title for your report"}
    )
    image = FileField(
        'Upload Image',
        validators=[FileAllowed(['jpg', 'jpeg', 'png'], 'Images only!')],
        render_kw={"accept": "image/*"}
    )
    notes = TextAreaField(
        'Notes',
        validators=[Optional()],
        render_kw={"placeholder": "Enter any notes regarding the issue (optional)"}
    )
    # New field: Users can submit tags as comma separated values when creating a report.
    tags = StringField(
        'Tags (comma separated)',
        validators=[Optional()],
        render_kw={"placeholder": "e.g. Bug, UI, Urgent"}
    )
    submit = SubmitField('Post Report')

# Report Note form for adding notes to a report
class NoteForm(FlaskForm):
    content = TextAreaField(
        "Message",
        validators=[DataRequired(), Length(min=1, max=1000)],
        render_kw={"placeholder": "Enter your note here..."}
    )
    submit = SubmitField("Post Note")

# Tag form for adding a tag using predefined choices (used in the report notes page)
class TagForm(FlaskForm):
    tag = SelectField('Select a Tag/Reason', choices=[
        ('', '-- Select a Tag --'),
        ('Tote Conveyance', 'Tote Conveyance'),
        ('Tote Lag / Out of Work', 'Tote Lag / Out of Work'),
        ('Damaged Tote', 'Damaged Tote'),
        ('Missing Tote', 'Missing Tote')
    ], validators=[Optional()])
    submit = SubmitField('Add Tag')