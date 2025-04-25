from flask import Blueprint

reports_bp = Blueprint('reports', __name__)

# Import submodules so their routes and helpers register with this blueprint.
from app.blueprints.reports import helpers, listing_routes, detail_routes, admin_routes