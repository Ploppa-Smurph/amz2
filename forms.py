# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
from flask_wtf.file import FileField, FileAllowed
from models import User

class RegistrationForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired(), Length(min=2, max=20)]
    )
    email = StringField(
        'Email',
        validators=[DataRequired(), Email()]
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

class LoginForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired(), Length(min=2, max=20)]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired()]
    )
    submit = SubmitField('Login')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField(
        'Email',
        validators=[DataRequired(), Email()]
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

# Updated ReportForm for submitting a new report with image and notes.
class ReportForm(FlaskForm):
    title = StringField(
        'Title',
        validators=[DataRequired(), Length(max=100)],
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
    submit = SubmitField('Post Report')

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