import json
import logging
import os
from datetime import datetime

import boto3

from db_operations import db

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID")
COGNITO_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID")
COGNITO_REGION = os.environ.get("AWS_REGION", "eu-west-2")

HTTP_OK = 200
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_NOT_FOUND = 404
HTTP_TOO_MANY = 429
HTTP_INTERNAL_ERROR = 500

ALLOWED_ROLES = [
    "admin",
    "artisan",
    "customer"
]


def construct_response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS"
        },
        "body": json.dumps(body, default=str)
    }


def get_cognito_client():
    return boto3.client(
        "cognito-idp",
        region_name=COGNITO_REGION
    )


def parse_body(event):
    try:
        body = event.get("body")

        if isinstance(body, dict):
            return body

        return json.loads(body or "{}")

    except json.JSONDecodeError:
        raise ValueError("Invalid JSON format")


def get_bearer_token(event):
    headers = event.get("headers", {})

    auth_header = (
        headers.get("Authorization")
        or headers.get("authorization")
        or ""
    )

    if auth_header.startswith("Bearer "):
        return auth_header.split(" ")[1]

    return None


def get_cognito_sub(email):
    try:
        cognito_client = get_cognito_client()

        response = cognito_client.admin_get_user(
            UserPoolId=COGNITO_POOL_ID,
            Username=email
        )

        attributes = {
            item["Name"]: item["Value"]
            for item in response["UserAttributes"]
        }

        return attributes.get("sub")

    except Exception:
        logger.exception(
            "Unable to retrieve Cognito sub for %s",
            email
        )
        return None


def get_cognito_user(access_token):
    cognito_client = get_cognito_client()

    response = cognito_client.get_user(
        AccessToken=access_token
    )

    return {
        item["Name"]: item["Value"]
        for item in response["UserAttributes"]
    }


def normalize_email(email):
    if not email:
        return ""

    return email.strip().lower()


def require_fields(data, fields):
    missing = []

    for field in fields:
        value = data.get(field)

        if value is None or value == "":
            missing.append(field)

    return missing

def register(event, context):
    try:
        body_data = json.loads(event.get("body", "{}"))

        required_fields = ["email", "password", "name", "role"]

        missing = [
            field for field in required_fields
            if not body_data.get(field)
        ]

        if missing:
            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": f"Missing required fields: {', '.join(missing)}"
                }
            )

        email = body_data["email"].strip().lower()
        password = body_data["password"]
        name = body_data["name"].strip()
        role = body_data["role"].strip().lower()

        if role not in ALLOWED_ROLES:
            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": f"Role must be one of: {', '.join(ALLOWED_ROLES)}"
                }
            )

        cognito_client = get_cognito_client()

        try:

            cognito_client.sign_up(
                ClientId=COGNITO_CLIENT_ID,
                Username=email,
                Password=password,
                UserAttributes=[
                    {
                        "Name": "email",
                        "Value": email
                    },
                    {
                        "Name": "name",
                        "Value": name
                    },
                    {
                        "Name": "custom:role",
                        "Value": role
                    }
                ]
            )

        except cognito_client.exceptions.UsernameExistsException:

            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": "An account already exists with this email."
                }
            )

        except cognito_client.exceptions.InvalidPasswordException as e:

            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": str(e)
                }
            )

        except cognito_client.exceptions.InvalidParameterException as e:

            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": str(e)
                }
            )

        cognito_sub = get_cognito_sub(email)

        if not cognito_sub:

            return construct_response(
                HTTP_INTERNAL_ERROR,
                {
                    "error": "Failed to retrieve Cognito user identifier."
                }
            )

        user_payload = {
            "cognito_sub": cognito_sub,
            "email": email,
            "name": name,
            "role": role,
            "is_active": 1,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }

        user_result = db.insert_user(user_payload)

        if user_result["statusCode"] != HTTP_OK:
            return construct_response(
                user_result["statusCode"],
                user_result["body"]
            )

        logger.info(
            "New user registered successfully: %s",
            email
        )

        return construct_response(
            HTTP_CREATED,
            {
                "message": "Registration successful. Please verify your email.",
                "user": {
                    "cognito_sub": cognito_sub,
                    "email": email,
                    "name": name,
                    "role": role
                }
            }
        )

    except json.JSONDecodeError:

        return construct_response(
            HTTP_BAD_REQUEST,
            {
                "error": "Invalid JSON format."
            }
        )

    except Exception:

        logger.exception("register() failed")

        return construct_response(
            HTTP_INTERNAL_ERROR,
            {
                "error": "Internal server error."
            }
        )

def login(event, context):
    try:

        body_data = json.loads(event.get("body", "{}"))

        email = body_data.get(
            "email",
            ""
        ).strip().lower()

        password = body_data.get(
            "password",
            ""
        )

        if not email:
            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": "Email is required."
                }
            )

        if not password:
            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": "Password is required."
                }
            )

        cognito_client = get_cognito_client()

        try:

            auth_response = cognito_client.initiate_auth(
                ClientId=COGNITO_CLIENT_ID,
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={
                    "USERNAME": email,
                    "PASSWORD": password
                }
            )

        except cognito_client.exceptions.NotAuthorizedException:

            return construct_response(
                HTTP_UNAUTHORIZED,
                {
                    "error": "Incorrect email or password."
                }
            )

        except cognito_client.exceptions.UserNotFoundException:

            return construct_response(
                HTTP_UNAUTHORIZED,
                {
                    "error": "Incorrect email or password."
                }
            )

        except cognito_client.exceptions.UserNotConfirmedException:

            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": "Please verify your email before logging in."
                }
            )

        except cognito_client.exceptions.PasswordResetRequiredException:

            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": "Password reset required."
                }
            )

        tokens = auth_response["AuthenticationResult"]

        user_response = cognito_client.get_user(
            AccessToken=tokens["AccessToken"]
        )

        attrs = {
            attr["Name"]: attr["Value"]
            for attr in user_response["UserAttributes"]
        }

        logger.info(
            "User login successful: %s",
            email
        )

        return construct_response(
            HTTP_OK,
            {
                "message": "Login successful.",
                "access_token": tokens["AccessToken"],
                "id_token": tokens["IdToken"],
                "refresh_token": tokens.get("RefreshToken"),
                "expires_in": tokens["ExpiresIn"],
                "token_type": tokens["TokenType"],
                "user": {
                    "id": attrs.get("sub"),
                    "email": attrs.get("email"),
                    "name": attrs.get("name"),
                    "role": attrs.get("custom:role"),
                    "email_verified": (
                        attrs.get("email_verified") == "true"
                    )
                }
            }
        )

    except json.JSONDecodeError:

        return construct_response(
            HTTP_BAD_REQUEST,
            {
                "error": "Invalid JSON format."
            }
        )

    except Exception:

        logger.exception("login() failed")

        return construct_response(
            HTTP_INTERNAL_ERROR,
            {
                "error": "Internal server error."
            }
        )

def forgot_password(event, context):
    try:

        body_data = json.loads(event.get("body", "{}"))

        email = body_data.get(
            "email",
            ""
        ).strip().lower()

        if not email:
            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": "Email is required."
                }
            )

        cognito_client = get_cognito_client()

        try:

            cognito_client.forgot_password(
                ClientId=COGNITO_CLIENT_ID,
                Username=email
            )

        except cognito_client.exceptions.UserNotFoundException:

            # Prevent email enumeration
            return construct_response(
                HTTP_OK,
                {
                    "message": "If an account exists, a password reset code has been sent."
                }
            )

        except cognito_client.exceptions.InvalidParameterException:

            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": "Please verify your email address before resetting your password."
                }
            )

        except cognito_client.exceptions.LimitExceededException:

            return construct_response(
                HTTP_TOO_MANY,
                {
                    "error": "Too many requests. Please try again later."
                }
            )

        logger.info(
            "Password reset requested for: %s",
            email
        )

        return construct_response(
            HTTP_OK,
            {
                "message": "If an account exists, a password reset code has been sent.",
                "email": email
            }
        )

    except json.JSONDecodeError:

        return construct_response(
            HTTP_BAD_REQUEST,
            {
                "error": "Invalid JSON format."
            }
        )

    except Exception:

        logger.exception(
            "forgot_password() failed"
        )

        return construct_response(
            HTTP_INTERNAL_ERROR,
            {
                "error": "Internal server error."
            }
        )

def reset_password(event, context):
    try:

        body_data = json.loads(event.get("body", "{}"))

        email = body_data.get(
            "email",
            ""
        ).strip().lower()

        code = body_data.get(
            "code",
            ""
        ).strip()

        new_password = body_data.get(
            "new_password",
            ""
        )

        if not email:
            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": "Email is required."
                }
            )

        if not code:
            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": "Verification code is required."
                }
            )

        if not new_password:
            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": "New password is required."
                }
            )

        cognito_client = get_cognito_client()

        try:

            cognito_client.confirm_forgot_password(
                ClientId=COGNITO_CLIENT_ID,
                Username=email,
                ConfirmationCode=code,
                Password=new_password
            )

        except cognito_client.exceptions.CodeMismatchException:

            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": "Invalid verification code."
                }
            )

        except cognito_client.exceptions.ExpiredCodeException:

            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": "Verification code has expired. Please request a new one."
                }
            )

        except cognito_client.exceptions.InvalidPasswordException as e:

            return construct_response(
                HTTP_BAD_REQUEST,
                {
                    "error": str(e)
                }
            )

        except cognito_client.exceptions.UserNotFoundException:

            return construct_response(
                HTTP_NOT_FOUND,
                {
                    "error": "Account not found."
                }
            )

        except cognito_client.exceptions.LimitExceededException:

            return construct_response(
                HTTP_TOO_MANY,
                {
                    "error": "Too many attempts. Please try again later."
                }
            )

        logger.info(
            "Password reset completed for %s",
            email
        )

        return construct_response(
            HTTP_OK,
            {
                "message": "Password reset successful. You can now log in with your new password.",
                "email": email
            }
        )

    except json.JSONDecodeError:

        return construct_response(
            HTTP_BAD_REQUEST,
            {
                "error": "Invalid JSON format."
            }
        )

    except Exception:

        logger.exception(
            "reset_password() failed"
        )

        return construct_response(
            HTTP_INTERNAL_ERROR,
            {
                "error": "Internal server error."
            }
        )
