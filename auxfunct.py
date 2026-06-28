import re
import boto3

ses = boto3.client("ses", region_name="us-east-1")  # your AWS region

def send_email(to_email, subject, body):
    ses.send_email(
        Source="noreply@yourdomain.com",  # must be verified in SES
        Destination={
            "ToAddresses": [to_email]
        },
        Message={
            "Subject": {"Data": subject},
            "Body": {
                "Html": {"Data": body}
            }
        }
    )

def validate_password(password: str) -> bool:
    """
    Password must:
    - Be at least 8 characters long
    - Contain at least one uppercase letter
    - Contain at least one lowercase letter
    - Contain at least one digit
    - Contain at least one special character
    """
    if not password or len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[^A-Za-z0-9]', password):
        return False
    return True