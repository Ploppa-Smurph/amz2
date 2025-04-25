# File: app/utils/report_helpers.py
from datetime import datetime

def safe_parse_date(date_str, fmt='%Y-%m-%d'):
    """
    Attempts to parse a date string with the given format.
    Returns a datetime object on success; None on failure.
    """
    try:
        return datetime.strptime(date_str, fmt)
    except (ValueError, TypeError):
        return None

def group_reports_by_day(reports_list):
    """
    Groups a list of report objects by the date component of their
    exif_datetime (if present) or date_posted.
    Returns a dictionary with keys as dates sorted in descending order.
    """
    grouped = {}
    for report in reports_list:
        taken = report.exif_datetime if report.exif_datetime else report.date_posted
        day = taken.date()
        grouped.setdefault(day, []).append(report)
    # Return a dictionary sorted by day in descending order.
    return dict(sorted(grouped.items(), key=lambda item: item[0], reverse=True))

def paginate(items, page, page_size):
    """
    Paginates a list of items.
    Returns a tuple: (paginated_items, pagination_dict)
    """
    total_count = len(items)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated = items[start_idx:end_idx]
    total_pages = (total_count + page_size - 1) // page_size
    pagination = {
        "current_page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "total_count": total_count
    }
    return paginated, pagination