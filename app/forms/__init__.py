# Import and re-export all the forms from forms.py and admin_forms.py
from .forms import (
    RegistrationForm,
    LoginForm,
    ResetPasswordRequestForm,
    ResetPasswordForm,
    FirstTimePasswordChangeForm,
    ReportForm,
    NoteForm,
    TagForm
)
from .admin_forms import RoleChangeForm, AdminCreateUserForm

# Optionally you can define __all__ for explicit exports:
__all__ = [
    "RegistrationForm",
    "LoginForm",
    "ResetPasswordRequestForm",
    "ResetPasswordForm",
    "FirstTimePasswordChangeForm",
    "ReportForm",
    "NoteForm",
    "RoleChangeForm",
    "AdminCreateUserForm",
    "TagForm"
]
