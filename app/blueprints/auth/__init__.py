from flask import Blueprint

auth_bp = Blueprint('auth', __name__)

# Import submodules so their routes and helpers register with the blueprint.
from app.blueprints.auth import helpers, profile_routes, public_routes, admin_routes