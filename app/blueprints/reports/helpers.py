from datetime import datetime

def safe_parse_date(date_str, fmt='%Y-%m-%d'):
    """
    Attempt to parse a date string with the given format.
    Return the parsed datetime object on success, or None on failure.
    """
    try:
        return datetime.strptime(date_str, fmt)
    except (ValueError, TypeError):
        return None

def group_reports_by_day(reports_list):
    """
    Groups a list of Report objects by the date component of their
    exif_datetime (if present) or date_posted.
    Returns a dict with date keys sorted in descending order.
    """
    grouped = {}
    for report in reports_list:
        taken = report.exif_datetime if report.exif_datetime else report.date_posted
        day = taken.date()
        grouped.setdefault(day, []).append(report)
    # Sort by day (most recent first)
    return dict(sorted(grouped.items(), key=lambda item: item[0], reverse=True))

def paginate(items, page, page_size):
    """
    Returns a slice of items for the given page number and page size,
    along with a pagination dictionary.
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