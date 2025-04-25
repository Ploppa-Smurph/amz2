from flask import render_template
from flask_login import login_required, current_user
from app.blueprints.auth import auth_bp
from app.blueprints.auth.helpers import get_admin_grouped_reports, get_manager_reports_by_author, get_user_day_counts
from app.models import Report   # For ensuring Report gets imported (if needed)

@auth_bp.route('/profile', methods=['GET'])
@login_required
def profile():
    """
    Displays a user’s profile page. For:
      - Admin: grouped reports by role.
      - Manager: grouped reports by author.
      - Regular user: reports aggregated by day.
    """
    if current_user.role == "admin":
        admin_grouped = get_admin_grouped_reports()
        return render_template("profile.html", user=current_user, admin_grouped_reports=admin_grouped)
    elif current_user.role == "manager":
        reports_by_author = get_manager_reports_by_author()
        return render_template("profile.html", user=current_user, reports_by_author=reports_by_author)
    else:
        day_counts, sorted_days, default_day = get_user_day_counts()
        return render_template("profile.html", user=current_user, day_counts=day_counts,
                               sorted_days=sorted_days, default_day=default_day)