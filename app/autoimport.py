import os
import mimetypes
from datetime import datetime, timezone
from app import create_app  # Import factory function
app = create_app()         # Create an application instance
from app.extensions import db
from app.models import Report, User
from app.utils.amazon_utils import list_images, get_exif_datetime  # Updated import path
import boto3

# Ensure your bucket name and region are set in the environment variables
S3_BUCKET = os.getenv('S3_BUCKET_NAME')
AWS_REGION = os.getenv('AWS_DEFAULT_REGION')

# Create an S3 client
s3_client = boto3.client('s3', region_name=AWS_REGION)

def get_image_data(s3_key):
    try:
        response = s3_client.get_object(Bucket=S3_BUCKET, Key=s3_key)
        image_data = response['Body'].read()
        # Attempt to determine the image MIME type.
        mimetype = response.get('ContentType') or mimetypes.guess_type(s3_key)[0] or 'application/octet-stream'
        print(f"Retrieved {len(image_data)} bytes from {s3_key} with mimetype {mimetype}")
        return image_data, mimetype
    except Exception as e:
        print(f"Error retrieving {s3_key}: {e}")
        return None, None

def main():
    with app.app_context():
        user = User.query.filter_by(username='ploppa').first()
        if not user:
            print("User not found. Please specify a valid username.")
            return

        images_data = list_images(page=1, page_size=10000)
        images = images_data.get('images', [])
        if not images:
            print("No images found in the S3 bucket.")
            return

        for image in images:
            s3_key = image.get('key')
            # Check if a report for this S3 key already exists using the new s3_key field.
            existing = Report.query.filter_by(s3_key=s3_key).first()
            if existing:
                print(f"Report for key '{s3_key}' already exists. Skipping duplicate.")
                continue

            img_data, mimetype = get_image_data(s3_key)
            # Only add a report if image data is properly retrieved.
            if not img_data:
                print(f"Skipping {s3_key} due to missing image data.")
                continue

            # Retrieve the EXIF date for this image.
            exif_dt = get_exif_datetime(s3_key)
            if not exif_dt:
                # Fall back to the current time if EXIF metadata is missing.
                exif_dt = datetime.now(timezone.utc)

            # Create a report that stores the S3 key and the extracted EXIF datetime.
            report = Report(
                title=s3_key,
                notes=f"Image taken on {exif_dt.isoformat()}",
                image_data=img_data,
                image_mimetype=mimetype,
                s3_key=s3_key,
                exif_datetime=exif_dt,
                author=user
            )
            # Optionally, set the report's posting time.
            report.date_posted = exif_dt

            db.session.add(report)
            print(f"Imported report for key: {s3_key}")

        try:
            db.session.commit()
            print("Finished importing reports.")
        except Exception as e:
            db.session.rollback()
            print(f"Error committing reports to the database: {e}")

if __name__ == '__main__':
    main()