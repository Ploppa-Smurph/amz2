# blueprints/auth/routes.py
from flask import Blueprint, render_template, redirect, url_for, flash, request
from forms import RegistrationForm, LoginForm
from models import User
from extensions import db
from flask_login import login_user, logout_user, current_user
try:
    from werkzeug.urls import url_parse
except ImportError:
    try:
        from werkzeug.http import parse_url as url_parse
    except ImportError:
        from urllib.parse import urlparse as url_parse

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('register.html', title='Register', form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Login unsuccessful. Please check your username and password.', 'danger')
            return redirect(url_for('auth.login'))
        login_user(user)
        next_page = request.args.get('next')
        # Security check for redirection
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('home')
        return redirect(next_page)
    return render_template('login.html', title='Login', form=form)

@auth_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@auth_bp.route('/profile')
def profile():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    return render_template('profile.html', user=current_user)