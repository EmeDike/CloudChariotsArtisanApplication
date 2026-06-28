import re
import boto3

ses = boto3.client("ses", region_name="eu-west-2")  # ← change region from us-east-1

def send_email(to_email, subject, body):
    ses.send_email(
        Source="dicksoneme22@gmail.com",  # ← change to your verified email
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