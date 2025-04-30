from flask import render_template, redirect, url_for, flash, request, current_app, session
from flask_login import login_user, logout_user, current_user
from app.forms import RegistrationForm, LoginForm, ResetPasswordRequestForm, ResetPasswordForm, FirstTimePasswordChangeForm
from app.models import User
from app.extensions import db
from datetime import datetime
from collections import defaultdict
from app.blueprints.auth import auth_bp
from app.blueprints.auth.helpers import send_reset_email
try:
    from werkzeug.urls import url_parse
except ImportError:
    from urllib.parse import urlparse as url_parse

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Disallow using "admin" (case insensitive) as a username.
        if form.username.data.strip().lower() == 'admin':
            flash("The username 'admin' is reserved for system administration. Please choose another username.", "danger")
            return redirect(url_for("auth.register"))
            
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash("Username already taken. Please choose another one.", "danger")
            return redirect(url_for("auth.register"))

        # For self-registered accounts, set must_change_password to False.
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            role="user",
            must_change_password=False
        )
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash("There was an error creating your account. Please try again.", "danger")
            return redirect(url_for("auth.register"))

        flash("Account created successfully!", "success")
        return redirect(url_for("auth.login"))
    return render_template("register.html", form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    show_forgot = False
    show_register = False

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Login unsuccessful. Please check your username and password.', 'danger')
            show_forgot = True
            show_register = True
        else:
            login_user(user)
            session['server_run_id'] = current_app.config['SERVER_RUN_ID']
            if user.must_change_password:
                return redirect(url_for('auth.force_change_password'))
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('auth.profile')
            flash('Login successful!', 'success')
            return redirect(next_page)
    return render_template('login.html', title='Login', form=form, show_forgot=show_forgot, show_register=show_register)

@auth_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

# Route for users to request password reset link via email
@auth_bp.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.get_reset_token()  # Defined in models.py
            send_reset_email(user, token)
        flash('If an account with that email exists, instructions to reset your password have been sent.', 'info')
        return redirect(url_for('auth.login'))
    return render_template('reset_password_request.html', title='Reset Password', form=form)

# Route to reset password using the token sent via email
@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if not user:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('auth.reset_password_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('reset_password.html', title='Reset Password', form=form)

@auth_bp.route('/force_change_password', methods=['GET', 'POST'])
def force_change_password():
    from flask_login import login_required
    # Decorate with login_required (or decorate the function)
    if not current_user.must_change_password:
        return redirect(url_for('home'))
    form = FirstTimePasswordChangeForm()
    if form.validate_on_submit():
        current_user.set_password(form.new_password.data)
        current_user.must_change_password = False
        db.session.commit()
        flash("Your password has been updated.", "success")
        return redirect(url_for('auth.profile'))
    return render_template('force_change_password.html', title="Change Password", form=form)