import os
import boto3
import mimetypes
from datetime import datetime
from io import BytesIO
from botocore.exceptions import ClientError
from PIL import Image, ExifTags
from urllib.parse import quote

# Get bucket name and region from environment variables (adjust defaults as needed)
S3_BUCKET = os.getenv('S3_BUCKET_NAME', 'amz-station')
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-2')  # Adjust as needed

# Create an S3 client in the specified region
s3_client = boto3.client('s3', region_name=AWS_REGION)

def get_public_url(key):
    """
    Construct and return the public URL for an S3 object, ensuring the key is URL encoded.
    """
    encoded_key = quote(key)
    return f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{encoded_key}"

def get_exif_datetime(key):
    """
    Retrieve the EXIF DateTimeOriginal (or DateTime) field from the image stored in S3.
    Returns a datetime object if extraction is successful; otherwise, None.
    """
    try:
        response = s3_client.get_object(Bucket=S3_BUCKET, Key=key)
        body = response['Body'].read()
        image_file = BytesIO(body)
        image = Image.open(image_file)
        exif_data = image._getexif()
        if exif_data:
            # Try DateTimeOriginal first
            for tag, value in exif_data.items():
                decoded = ExifTags.TAGS.get(tag, tag)
                if decoded == 'DateTimeOriginal':
                    dt = datetime.strptime(value, '%Y:%m:%d %H:%M:%S')
                    print(f"EXIF DateTimeOriginal for {key}: {dt}")
                    return dt
            # Fallback to DateTime if DateTimeOriginal isn't found
            for tag, value in exif_data.items():
                decoded = ExifTags.TAGS.get(tag, tag)
                if decoded == 'DateTime':
                    dt = datetime.strptime(value, '%Y:%m:%d %H:%M:%S')
                    print(f"EXIF DateTime for {key}: {dt}")
                    return dt
        print("EXIF date not found for key:", key)
    except Exception as e:
        print("Error reading EXIF for key", key, e)
    return None

def list_images(page=1, page_size=20):
    """
    List a paginated set of image files from the S3 bucket.
    Returns a dictionary containing the paginated images and pagination metadata.
    """
    paginator = s3_client.get_paginator('list_objects_v2')
    pages = paginator.paginate(Bucket=S3_BUCKET)

    all_images = []
    for page_data in pages:
        if 'Contents' in page_data:
            for obj in page_data['Contents']:
                key = obj['Key']
                if key.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
                    exif_dt = get_exif_datetime(key)
                    if exif_dt is None:
                        exif_dt = obj['LastModified']
                        print(f"Using LastModified for {key}: {exif_dt}")
                    all_images.append({
                        'key': key,
                        'exif_date': exif_dt,
                        'url': get_public_url(key)
                    })

    # Sort images by EXIF date
    all_images.sort(key=lambda x: x['exif_date'])

    # Pagination logic
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated_images = all_images[start_idx:end_idx]

    return {
        'images': paginated_images,
        'total_count': len(all_images),
        'page': page,
        'page_size': page_size
    }

def verify_public_url(url):
    """
    Verify the given public URL by making an HTTP GET request.
    Prints the HTTP status code and the Content-Type header.
    """
    try:
        import requests
        response = requests.get(url)
        print("Verifying URL:", url)
        print("Status Code:", response.status_code)
        print("Content-Type:", response.headers.get('Content-Type'))
    except Exception as e:
        print("Error verifying URL:", e)

if __name__ == '__main__':
    images_data = list_images()
    images = images_data['images']
    if images:
        test_url = images[0]['url']
        print("Testing URL for key:", images[0]['key'])
        verify_public_url(test_url)
    else:
        print("No images found to test.")