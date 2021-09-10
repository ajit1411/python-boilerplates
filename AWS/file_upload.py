import boto3
from botocore.client import Config

def lambda_handler(event, context):
    try:
        s3Client = boto3.client("s3")
    except Exception as e:
        return {
            "status_code": 400,
            "error": e
        }
        
    bucketName = event.get('body-json').get('bucket_name')
    fileKey = event.get('body-json').get('file_key')
    expiryTime = event.get('body-json').get('expiry_time')
    action = event.get('body-json').get('action')
    try:
        URL = s3Client.generate_presigned_url(
            "put_object" if action=="upload" else "get_object",
            Params = {"Bucket": bucketName,"Key": fileKey},
            ExpiresIn = expiryTime
            )
        return {
            "status_code" : 200,
            "url" : URL
        }
    except Exception as e:
        return {
            "status_code" : 400,
            "error": e
        }