from flask import render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models import User
from app.extensions import db
from app.blueprints.auth import auth_bp
from app.forms.admin_forms import RoleChangeForm, AdminCreateUserForm
from app.blueprints.auth.helpers import admin_required

@auth_bp.route('/admin/change_role/<int:user_id>', methods=['GET', 'POST'])
@login_required
def change_role(user_id):
    if not admin_required():
        flash("You do not have permission to update roles.", "danger")
        return redirect(url_for('home'))
    user_to_update = User.query.get_or_404(user_id)
    form = RoleChangeForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for('auth.change_role', user_id=user_id))
        user_to_update.role = form.role.data
        db.session.commit()
        flash(f"Updated role for user {user_to_update.username} to {form.role.data}.", "success")
        return redirect(url_for('auth.user_list'))
    form.role.data = user_to_update.role
    return render_template('admin/change_role.html', user=user_to_update, form=form)

@auth_bp.route('/admin/user_list')
@login_required
def user_list():
    if not admin_required():
        flash("You do not have permission to view this page.", "danger")
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin/user_list.html', users=users)

@auth_bp.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if not admin_required():
        flash("You do not have permission to create users.", "danger")
        return redirect(url_for('home'))
    form = AdminCreateUserForm()
    if form.validate_on_submit():
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data  # Can be "user", "manager", or "admin"
        )
        new_user.set_password(form.temp_password.data)
        new_user.must_change_password = True  # Force the new user to change their password
        db.session.add(new_user)
        db.session.commit()
        flash("User created. They will be required to set a new password on first login.", "success")
        return redirect(url_for('auth.user_list'))
    return render_template('admin/create_user.html', form=form)