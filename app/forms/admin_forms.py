# admin_forms.py
from flask_wtf import FlaskForm
from wtforms import SelectField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo

class RoleChangeForm(FlaskForm):
    role = SelectField(
        'Role',
        choices=[("user", "User"), ("manager", "Manager"), ("admin", "Admin")],
        validators=[DataRequired()],
        render_kw={"class": "form-control"}
    )
    current_password = PasswordField(
        'Your Current Password',
        validators=[DataRequired()],
        render_kw={
            "placeholder": "Enter your current password",
            "class": "form-control"
        }
    )
    submit = SubmitField(
        'Update Role',
        render_kw={"class": "btn btn-primary"}
    )

class AdminCreateUserForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired(), Length(min=2, max=20)],
        render_kw={"placeholder": "Enter username", "class": "form-control"}
    )
    email = StringField(
        'Email',
        validators=[DataRequired(), Email()],
        render_kw={"placeholder": "Enter email", "class": "form-control"}
    )
    role = SelectField(
        'Role',
        choices=[("user", "User"), ("manager", "Manager"), ("admin", "Admin")],
        validators=[DataRequired()],
        render_kw={"class": "form-control"}
    )
    temp_password = PasswordField(
        'Temporary Password',
        validators=[DataRequired(), Length(min=6)],
        render_kw={"placeholder": "Enter temporary password", "class": "form-control"}
    )
    confirm_temp_password = PasswordField(
        'Confirm Temporary Password',
        validators=[DataRequired(), EqualTo('temp_password')],
        render_kw={"placeholder": "Confirm temporary password", "class": "form-control"}
    )
    submit = SubmitField(
        'Create User',
        render_kw={"class": "btn btn-primary"}
    )