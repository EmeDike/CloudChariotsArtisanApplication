import json
import logging
import os
from datetime import datetime, timedelta

import boto3
import pymysql
from db_operations import db, connection

import auxfunct
from db_operations import db

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID")
COGNITO_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID")
COGNITO_REGION = os.environ.get("AWS_REGION", "eu-west-2")

HTTP_OK = 200
HTTP_FORBIDDEN = 403
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_NOT_FOUND = 404
HTTP_TOO_MANY = 429
HTTP_INTERNAL_ERROR = 500
from botocore.exceptions import ClientError
client = boto3.client("cognito-idp", region_name=COGNITO_REGION)


ALLOWED_ROLES = [
    "admin",
    "artisan",
    "customer"
]

def get_artisan_from_token(event):
    """
    Extract artisan_id from Cognito JWT claims.
    Flow: JWT → cognito_sub → tbl_users.user_id → tbl_artisans.artisan_id
    """
    claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
    cognito_sub = claims["sub"]

    connection.ping(reconnect=True)
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute("""
            SELECT a.artisan_id, a.business_name, a.is_available,
                   a.verification_status, a.average_rating, a.total_reviews,
                   u.user_id, u.first_name, u.last_name, u.email, u.phone_number
            FROM tbl_users u
            INNER JOIN tbl_artisans a ON a.user_id = u.user_id
            WHERE u.cognito_sub = %s
            LIMIT 1
        """, (cognito_sub,))
        return cursor.fetchone()

def user_login(event, context):
    body = json.loads(event.get("body", "{}"))
    email = body.get("email", "").strip().lower()
    user_pass = body.get("password", "")

    if not email or not user_pass:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"success": False, "error": "Email and password are required"})
        }

    try:
        auth_response = client.initiate_auth(
            ClientId=COGNITO_CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": email,
                "PASSWORD": user_pass
            }
        )
        tokens = auth_response["AuthenticationResult"]

        cursor = connection.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM tbl_users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()

        if not user:
            return {
                "statusCode": 404,
                "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body": json.dumps({"success": False, "error": "User not found in database"})
            }

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps({
                "success": True,
                "data": {
                    "token": tokens["IdToken"],
                    "access_token": tokens["AccessToken"],
                    "refresh_token": tokens["RefreshToken"],
                    "user": {
                        "id": user["user_id"],
                        "email": user["email"],
                        "full_name": f"{user['first_name']} {user['last_name']}",
                        "role": user["role"],
                        "phone": user.get("phone_number"),
                        "profile_image": None,
                        "is_verified": bool(user.get("is_active", False))
                    }
                }
            }, default=str)
        }

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "NotAuthorizedException":
            return {
                "statusCode": 401,
                "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body": json.dumps({"success": False, "error": "Invalid email or password"})
            }
        elif error_code == "UserNotFoundException":
            return {
                "statusCode": 401,
                "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body": json.dumps({"success": False, "error": "Invalid email or password"})
            }
        elif error_code == "UserNotConfirmedException":
            return {
                "statusCode": 403,
                "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body": json.dumps({"success": False, "error": "Please verify your email first"})
            }
        else:
            return {
                "statusCode": 500,
                "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body": json.dumps({"success": False, "error": e.response["Error"]["Message"]})
            }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"success": False, "error": str(e)})
        }

def getArtiAvail(event, context):

    try:
        claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
        cognito_sub = claims["sub"]

        params = event.get("queryStringParameters") or {}
        artisan_id = params.get("artisan_id")

        if not artisan_id:
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "success": False,
                    "message": "artisan_id is required."
                })
            }

        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            cursor.execute(
                """
                SELECT user_id
                FROM tbl_users
                WHERE cognito_sub = %s
                LIMIT 1
                """,
                (cognito_sub,)
            )

            requesting_user = cursor.fetchone()

            if not requesting_user:
                return {
                    "statusCode": 404,
                    "body": json.dumps({
                        "success": False,
                        "message": "Authenticated user not found."
                    })
                }

            # Get weekly availability
            cursor.execute(
                """
                SELECT schedule_id, day_of_week, start_time, end_time, is_available
                FROM tbl_artisan_availability
                WHERE artisan_id = %s
                ORDER BY FIELD(day_of_week, 'Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')
                """,
                (artisan_id,)
            )

            availability = cursor.fetchall()

            # Get blocked dates
            cursor.execute(
                """
                SELECT id, blocked_date, reason
                FROM tbl_artisan_blocked_dates
                WHERE artisan_id = %s AND blocked_date >= CURDATE()
                ORDER BY blocked_date ASC
                """,
                (artisan_id,)
            )

            blocked_dates = cursor.fetchall()

        return {
            "statusCode": 200,
            "body": json.dumps({
                "success": True,
                "data": {
                    "artisan_id": int(artisan_id),
                    "availability": availability,
                    "blocked_dates": blocked_dates
                }
            }, default=str)
        }

    except Exception as e:

        return {
            "statusCode": 500,
            "body": json.dumps({
                "success": False,
                "message": "Internal server error.",
                "error": str(e)
            })
        }

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


def registerArtisan(event, context):
    try:
        # 1. Parse request
        body = event.get("body")
        body_data = body if isinstance(body, dict) else json.loads(body)

        # 2. Validate Address fields (matches tbl_address schema)
        required_address_fields = ["label", "address", "city", "state", "latitude", "longitude"]
        address_data = {k: body_data.get(k) for k in required_address_fields}
        missing_address = [k for k, v in address_data.items() if v is None]
        if missing_address:
            return construct_response(HTTP_BAD_REQUEST, {"error": f"Missing address fields: {', '.join(missing_address)}"})

        # 3. Validate Artisan fields (matches tbl_users + tbl_artisan schema)
        required_artisan_fields = [
            "first_name", "last_name", "email", "phone_number", "password",
            "business_name", "years_of_experience", "bio"
        ]
        artisan_data = {k: body_data.get(k) for k in required_artisan_fields}
        missing_artisan = [k for k, v in artisan_data.items() if v is None]
        if missing_artisan:
            return construct_response(HTTP_BAD_REQUEST, {"error": f"Missing artisan fields: {', '.join(missing_artisan)}"})

        # 4. Validate years_of_experience is a non-negative integer
        try:
            artisan_data["years_of_experience"] = int(artisan_data["years_of_experience"])
            if artisan_data["years_of_experience"] < 0:
                raise ValueError
        except (ValueError, TypeError):
            return construct_response(HTTP_BAD_REQUEST, {"error": "years_of_experience must be a non-negative integer."})

        # 5. Password validation
        if not auxfunct.validate_password(artisan_data["password"]):
            return construct_response(HTTP_BAD_REQUEST, {
                "error": "Password must be at least 8 characters long and contain letters and numbers."
            })

        # 6. Create Cognito user
        full_name = f"{artisan_data['first_name']} {artisan_data['last_name']}"
        cognito_client = boto3.client('cognito-idp', region_name=COGNITO_REGION)
        try:
            cognito_client.admin_create_user(
                UserPoolId=COGNITO_POOL_ID,
                Username=artisan_data["email"],
                UserAttributes=[
                    {'Name': 'email',          'Value': artisan_data["email"]},
                    {'Name': 'phone_number',   'Value': artisan_data["phone_number"]},
                    {'Name': 'name',           'Value': full_name},
                    {'Name': 'email_verified', 'Value': 'true'}
                ],
                TemporaryPassword=artisan_data["password"],
                MessageAction='SUPPRESS'
            )
            cognito_client.admin_set_user_password(
                UserPoolId=COGNITO_POOL_ID,
                Username=artisan_data["email"],
                Password=artisan_data["password"],
                Permanent=True
            )
        except cognito_client.exceptions.UsernameExistsException:
            return construct_response(HTTP_BAD_REQUEST, {"error": f"Artisan with email {artisan_data['email']} already exists in Cognito."})

        # 7. Fetch Cognito sub
        cognito_sub = get_cognito_sub(artisan_data["email"])
        if not cognito_sub:
            return construct_response(HTTP_INTERNAL_ERROR, {"error": "Failed to retrieve Cognito sub."})

        # 8. Insert into tbl_users first (tbl_artisan.user_id is a FK to tbl_users)
        users_data = {
            "cognito_sub":  cognito_sub,
            "first_name":   artisan_data["first_name"],
            "last_name":    artisan_data["last_name"],
            "email":        artisan_data["email"],
            "phone_number": artisan_data["phone_number"],
            "role":         "artisan",
            "is_active":    1,
            "created_at":   datetime.now(),
            "updated_at":   datetime.now()
        }
        user_result = db.insert_user(users_data)
        if user_result["statusCode"] != HTTP_OK:
            return construct_response(user_result["statusCode"], user_result["body"])
        user_id = user_result["body"].get("user_id")

        # 9. Insert Address into DB (tbl_address.user_id links to tbl_users)
        address_data["user_id"] = user_id
        address_result = db.insert_address(address_data)
        if address_result["statusCode"] != HTTP_OK:
            return construct_response(address_result["statusCode"], address_result["body"])

        # 10. Insert Artisan profile into DB (tbl_artisan)
        artisan_db_payload = {
            "user_id":             user_id,
            "business_name":       artisan_data["business_name"],
            "years_of_experience": artisan_data["years_of_experience"],
            "bio":                 artisan_data["bio"],
            "average_rating":      0.00,
            "total_reviews":       0,
            "verification_status": "pending",
            "is_available":        1,
            "created_at":          datetime.now(),
            "updated_at":          datetime.now()
        }
        artisan_result = db.insert_artisan(artisan_db_payload)
        if artisan_result["statusCode"] != HTTP_OK:
            return construct_response(artisan_result["statusCode"], artisan_result["body"])
        artisan_id = artisan_result["body"].get("artisan_id")

        # 11. Create Wallet for Artisan
        wallet_data = {
            "owner_id":   artisan_id,
            "owner_type": "artisan",
            "currency":   "NGN",
            "balance":    0.00,
            "status":     "active"
        }
        wallet_result = db.insert_wallet(wallet_data)

        # 12. Success Response
        return construct_response(HTTP_CREATED, {
            "message":     "Artisan registered successfully.",
            "user_id":     user_id,
            "artisan_id":  artisan_id,
            "wallet_id":   wallet_result["body"].get("wallet_id"),
            "cognito_sub": cognito_sub
        })

    except json.JSONDecodeError:
        return construct_response(HTTP_BAD_REQUEST, {"error": "Invalid JSON format."})
    except Exception as e:
        logger.exception("Internal Server Error")
        return construct_response(HTTP_INTERNAL_ERROR, {"error": f"Internal Server Error: {str(e)}"})

def registerCustomer(event, context):
    try:
        # 1. Parse request
        body = event.get("body")
        body_data = body if isinstance(body, dict) else json.loads(body)

        # 2. Validate Address fields (matches tbl_address schema)
        required_address_fields = ["label", "address", "city", "state", "latitude", "longitude"]
        address_data = {k: body_data.get(k) for k in required_address_fields}
        missing_address = [k for k, v in address_data.items() if v is None]
        if missing_address:
            return construct_response(HTTP_BAD_REQUEST, {"error": f"Missing address fields: {', '.join(missing_address)}"})

        # 3. Validate Customer fields (matches tbl_users schema)
        required_customer_fields = ["first_name", "last_name", "email", "phone_number", "password"]
        customer_data = {k: body_data.get(k) for k in required_customer_fields}
        missing_customer = [k for k, v in customer_data.items() if v is None]
        if missing_customer:
            return construct_response(HTTP_BAD_REQUEST, {"error": f"Missing customer fields: {', '.join(missing_customer)}"})

        # 4. Password validation
        if not auxfunct.validate_password(customer_data["password"]):
            return construct_response(HTTP_BAD_REQUEST, {
                "error": "Password must be at least 8 characters long and contain letters and numbers."
            })

        # 5. Create Cognito user
        full_name = f"{customer_data['first_name']} {customer_data['last_name']}"
        cognito_client = boto3.client('cognito-idp', region_name=COGNITO_REGION)
        try:
            cognito_client.admin_create_user(
                UserPoolId=COGNITO_POOL_ID,
                Username=customer_data["email"],
                UserAttributes=[
                    {'Name': 'email',          'Value': customer_data["email"]},
                    {'Name': 'phone_number',   'Value': customer_data["phone_number"]},
                    {'Name': 'name',           'Value': full_name},
                    {'Name': 'email_verified', 'Value': 'true'}
                ],
                TemporaryPassword=customer_data["password"],
                MessageAction='SUPPRESS'
            )
            cognito_client.admin_set_user_password(
                UserPoolId=COGNITO_POOL_ID,
                Username=customer_data["email"],
                Password=customer_data["password"],
                Permanent=True
            )
        except cognito_client.exceptions.UsernameExistsException:
            return construct_response(HTTP_BAD_REQUEST, {"error": f"Customer with email {customer_data['email']} already exists in Cognito."})

        # 6. Fetch Cognito sub
        cognito_sub = get_cognito_sub(customer_data["email"])
        if not cognito_sub:
            return construct_response(HTTP_INTERNAL_ERROR, {"error": "Failed to retrieve Cognito sub."})

        # 7. Insert into tbl_users first (tbl_customers.user_id is a FK to tbl_users)
        users_data = {
            "cognito_sub":  cognito_sub,
            "first_name":   customer_data["first_name"],
            "last_name":    customer_data["last_name"],
            "email":        customer_data["email"],
            "phone_number": customer_data["phone_number"],
            "role":         "customer",
            "is_active":    1,
            "created_at":   datetime.now(),
            "updated_at":   datetime.now()
        }
        user_result = db.insert_user(users_data)
        if user_result["statusCode"] != HTTP_OK:
            return construct_response(user_result["statusCode"], user_result["body"])
        user_id = user_result["body"].get("user_id")

        # 8. Insert Address into DB (tbl_address.user_id links to tbl_users)
        address_data["user_id"] = user_id
        address_result = db.insert_address(address_data)
        if address_result["statusCode"] != HTTP_OK:
            return construct_response(address_result["statusCode"], address_result["body"])

        # 9. Insert Customer profile into DB (tbl_customers)
        # - cognito_sub stored here directly as per tbl_customers schema
        # - player_id left as None (nullable) until push notification service is integrated
        # - profile_image left as None (nullable) until upload flow is implemented
        # - status defaults to "active" — customers are immediately usable unlike artisans
        customer_db_payload = {
            "user_id":       user_id,
            "cognito_sub":   cognito_sub,
            "player_id":     None,
            "profile_image": None,
            "status":        "active",
            "created_at":    datetime.now(),
            "updated_at":    datetime.now()
        }
        customer_result = db.insert_customer(customer_db_payload)
        if customer_result["statusCode"] != HTTP_OK:
            return construct_response(customer_result["statusCode"], customer_result["body"])
        customer_id = customer_result["body"].get("customer_id")

        # 10. Success Response
        return construct_response(HTTP_CREATED, {
            "message":     "Customer registered successfully.",
            "user_id":     user_id,
            "customer_id": customer_id,
            "cognito_sub": cognito_sub
        })

    except json.JSONDecodeError:
        return construct_response(HTTP_BAD_REQUEST, {"error": "Invalid JSON format."})
    except Exception as e:
        logger.exception("Internal Server Error")
        return construct_response(HTTP_INTERNAL_ERROR, {"error": f"Internal Server Error: {str(e)}"})


def registerAdmin(event, context):
    try:
        # 1. Parse request
        body = event.get("body")
        body_data = body if isinstance(body, dict) else json.loads(body)

        # 2. Validate Admin fields (matches tbl_users + tbl_admins schema)
        required_admin_fields = [
            "first_name", "last_name", "email", "phone_number", "password",
            "department", "designation"
        ]
        admin_data = {k: body_data.get(k) for k in required_admin_fields}
        missing_admin = [k for k, v in admin_data.items() if v is None]
        if missing_admin:
            return construct_response(HTTP_BAD_REQUEST, {"error": f"Missing admin fields: {', '.join(missing_admin)}"})

        # 3. Password validation
        if not auxfunct.validate_password(admin_data["password"]):
            return construct_response(HTTP_BAD_REQUEST, {
                "error": "Password must be at least 8 characters long and contain letters and numbers."
            })

        # 4. Create Cognito user
        full_name = f"{admin_data['first_name']} {admin_data['last_name']}"
        cognito_client = boto3.client('cognito-idp', region_name=COGNITO_REGION)
        try:
            cognito_client.admin_create_user(
                UserPoolId=COGNITO_POOL_ID,
                Username=admin_data["email"],
                UserAttributes=[
                    {'Name': 'email',          'Value': admin_data["email"]},
                    {'Name': 'phone_number',   'Value': admin_data["phone_number"]},
                    {'Name': 'name',           'Value': full_name},
                    {'Name': 'email_verified', 'Value': 'true'}
                ],
                TemporaryPassword=admin_data["password"],
                MessageAction='SUPPRESS'
            )
            cognito_client.admin_set_user_password(
                UserPoolId=COGNITO_POOL_ID,
                Username=admin_data["email"],
                Password=admin_data["password"],
                Permanent=True
            )
        except cognito_client.exceptions.UsernameExistsException:
            return construct_response(HTTP_BAD_REQUEST, {"error": f"Admin with email {admin_data['email']} already exists in Cognito."})

        # 5. Fetch Cognito sub
        cognito_sub = get_cognito_sub(admin_data["email"])
        if not cognito_sub:
            return construct_response(HTTP_INTERNAL_ERROR, {"error": "Failed to retrieve Cognito sub."})

        # 6. Insert into tbl_users first (tbl_admins.user_id is a FK to tbl_users)
        users_data = {
            "cognito_sub":  cognito_sub,
            "first_name":   admin_data["first_name"],
            "last_name":    admin_data["last_name"],
            "email":        admin_data["email"],
            "phone_number": admin_data["phone_number"],
            "role":         "admin",
            "is_active":    1,
            "created_at":   datetime.now(),
            "updated_at":   datetime.now()
        }
        user_result = db.insert_user(users_data)
        if user_result["statusCode"] != HTTP_OK:
            return construct_response(user_result["statusCode"], user_result["body"])
        user_id = user_result["body"].get("user_id")


        admin_db_payload = {
            "user_id":     user_id,
            "cognito_sub": cognito_sub,
            "department":  admin_data["department"],
            "designation": admin_data["designation"],
            "created_at":  datetime.now(),
            "updated_at":  datetime.now()
        }
        admin_result = db.insert_admin(admin_db_payload)
        if admin_result["statusCode"] != HTTP_OK:
            return construct_response(admin_result["statusCode"], admin_result["body"])
        admin_id = admin_result["body"].get("admin_id")

        # 8. Success Response
        return construct_response(HTTP_CREATED, {
            "message":     "Admin registered successfully.",
            "user_id":     user_id,
            "admin_id":    admin_id,
            "cognito_sub": cognito_sub
        })

    except json.JSONDecodeError:
        return construct_response(HTTP_BAD_REQUEST, {"error": "Invalid JSON format."})
    except Exception as e:
        logger.exception("Internal Server Error")
        return construct_response(HTTP_INTERNAL_ERROR, {"error": f"Internal Server Error: {str(e)}"})

def createJobRequest(event, context):

    try:
        claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
        cognito_sub = claims["sub"]

        body = event.get("body")

        if isinstance(body, str):
            body = json.loads(body)

        required_fields = [
            "serviceId",
            "title",
            "description",
            "serviceAddress",
            "preferredDate"
        ]

        missing_fields = [
            field for field in required_fields
            if not body.get(field)
        ]

        if missing_fields:
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "success": False,
                    "message": f"Missing required fields: {', '.join(missing_fields)}"
                })
            }

        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            cursor.execute(
                """
                SELECT user_id
                FROM tbl_users
                WHERE cognito_sub = %s
                LIMIT 1
                """,
                (cognito_sub,)
            )

            customer = cursor.fetchone()

            if not customer:
                return {
                    "statusCode": 404,
                    "body": json.dumps({
                        "success": False,
                        "message": "Authenticated customer not found."
                    })
                }

            customer_id = customer["user_id"]

            cursor.execute(
                """
                INSERT INTO tbl_job_requests
                (
                    customer_id,
                    service_id,
                    title,
                    description,
                    location_address,
                    preferred_date,
                    status
                )
                VALUES
                (%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    customer_id,
                    body["serviceId"],
                    body["title"],
                    body["description"],
                    body["serviceAddress"],
                    body["preferredDate"],
                    "pending"
                )
            )

            job_request_id = cursor.lastrowid

        connection.commit()

        return {
            "statusCode": 201,
            "body": json.dumps({
                "success": True,
                "jobRequestId": job_request_id,
                "customerId": customer_id,
                "status": "pending",
                "message": "Job request created successfully."
            })
        }

    except Exception as e:

        try:
            connection.rollback()
        except:
            pass

        return {
            "statusCode": 500,
            "body": json.dumps({
                "success": False,
                "message": "Internal server error.",
                "error": str(e)
            })
        }

def updateJobRequestStatus(event, context):

    try:

        claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
        cognito_sub = claims["sub"]

        body = event.get("body")

        if isinstance(body, str):
            body = json.loads(body)

        job_request_id = body.get("jobRequestId")  # ← now from body

        if not job_request_id:
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "success": False,
                    "message": "jobRequestId is required."
                })
            }

        status = body.get("status")

        if status not in ["accepted", "declined"]:
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "success": False,
                    "message": "Status must be either 'accepted' or 'declined'."
                })
            }

        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            cursor.execute(
                """
                SELECT user_id, role
                FROM tbl_users
                WHERE cognito_sub = %s
                LIMIT 1
                """,
                (cognito_sub,)
            )

            artisan = cursor.fetchone()

            if not artisan:
                return {
                    "statusCode": 404,
                    "body": json.dumps({
                        "success": False,
                        "message": "Authenticated artisan not found."
                    })
                }

            if artisan["role"] != "artisan":
                return {
                    "statusCode": 403,
                    "body": json.dumps({
                        "success": False,
                        "message": "Only artisans can perform this action."
                    })
                }

            artisan_id = artisan["user_id"]

            cursor.execute(
                """
                SELECT
                    job_request_id,
                    customer_id,
                    status,
                    artisan_id
                FROM tbl_job_requests
                WHERE job_request_id=%s
                LIMIT 1
                """,
                (job_request_id,)
            )

            job_request = cursor.fetchone()

            if not job_request:
                return {
                    "statusCode": 404,
                    "body": json.dumps({
                        "success": False,
                        "message": "Job request not found."
                    })
                }

            if job_request["status"] != "pending":
                return {
                    "statusCode": 400,
                    "body": json.dumps({
                        "success": False,
                        "message": "This job request has already been processed."
                    })
                }

            if status == "accepted":

                cursor.execute(
                    """
                    UPDATE tbl_job_requests
                    SET artisan_id=%s,
                        status='accepted'
                    WHERE job_request_id=%s
                    """,
                    (artisan_id, job_request_id)
                )

            else:

                cursor.execute(
                    """
                    INSERT IGNORE INTO tbl_job_request_declines
                    (job_request_id, artisan_id)
                    VALUES (%s,%s)
                    """,
                    (job_request_id, artisan_id)
                )

            cursor.execute(
                """
                SELECT email
                FROM tbl_users
                WHERE user_id=%s
                LIMIT 1
                """,
                (job_request["customer_id"],)
            )

            customer = cursor.fetchone()

        connection.commit()

        if customer:
            try:
                if status == "accepted":
                    auxfunct.send_email(
                        to_email=customer["email"],
                        subject="Your job request has been accepted!",
                        body=f"""
                            <h2>Good news!</h2>
                            <p>An artisan has accepted your job request <b>#{job_request_id}</b>.</p>
                            <p>Log in to confirm your booking.</p>
                        """
                    )
                else:
                    auxfunct.send_email(
                        to_email=customer["email"],
                        subject="Update on your job request",
                        body=f"""
                            <h2>Job Request Update</h2>
                            <p>An artisan has declined your job request <b>#{job_request_id}</b>.</p>
                            <p>Your request is still open and other artisans can accept it.</p>
                        """
                    )
            except Exception as email_error:
                print(f"Email failed: {email_error}")

        return {
            "statusCode": 200,
            "body": json.dumps({
                "success": True,
                "jobRequestId": int(job_request_id),
                "status": status,
                "message": f"Job request {status} successfully."
            })
        }

    except Exception as e:

        try:
            connection.rollback()
        except:
            pass

        return {
            "statusCode": 500,
            "body": json.dumps({
                "success": False,
                "message": "Internal server error.",
                "error": str(e)
            })
        }

def createBooking(event, context):
    """
    Create a new booking between a customer and an artisan.

    Request body (POST):
      - artisan_id (int): The artisan's ID (required)
      - service_id (int): The service being booked (required - used to look up price)
      - booking_date (str): Date in YYYY-MM-DD format (required)
      - booking_time (str): Time in HH:MM format (required)
      - description (str): Description of work needed (required)
      - address (str): Service location address (required)
      - estimated_price (float): Estimated/agreed price (optional)
    """
    try:
        # --- Auth ---
        claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
        cognito_sub = claims["sub"]

        connection.ping(reconnect=True)

        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute(
                "SELECT user_id, role, is_active FROM tbl_users WHERE cognito_sub = %s LIMIT 1",
                (cognito_sub,)
            )
            user = cursor.fetchone()

        if not user:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Authenticated user not found."
            })

        if user["role"].lower() != "customer":
            return construct_response(HTTP_FORBIDDEN, {
                "success": False,
                "message": "Only customers can create bookings."
            })

        if user["is_active"] != 1:
            return construct_response(HTTP_FORBIDDEN, {
                "success": False,
                "message": "Your account is inactive."
            })

        customer_id = user["user_id"]

        # --- Parse body ---
        body = event.get("body")
        if isinstance(body, str):
            body = json.loads(body)
        if body is None:
            body = {}

        required_fields = ["artisan_id", "booking_date", "booking_time", "description", "address"]
        missing_fields = [f for f in required_fields if not body.get(f)]
        if missing_fields:
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": f"Missing required fields: {', '.join(missing_fields)}"
            })

        artisan_id = int(body["artisan_id"])
        booking_date = body["booking_date"]  # YYYY-MM-DD
        booking_time = body["booking_time"]  # HH:MM
        description = body["description"].strip()
        address = body["address"].strip()
        estimated_price = float(body.get("estimated_price", 0))

        # Combine date and time into datetime for the DB column
        booking_datetime = f"{booking_date} {booking_time}:00"

        # --- Validate artisan exists and is available ---
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute(
                """
                SELECT a.artisan_id, a.is_available, a.verification_status, u.first_name, u.last_name
                FROM tbl_artisans a
                INNER JOIN tbl_users u ON u.user_id = a.user_id
                WHERE a.artisan_id = %s
                LIMIT 1
                """,
                (artisan_id,)
            )
            artisan = cursor.fetchone()

        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan not found."
            })

        if artisan["is_available"] != 1:
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": "This artisan is currently unavailable for bookings."
            })

        if artisan["verification_status"] != "verified":
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": "This artisan is not yet verified."
            })

        # --- Create booking (matches existing tbl_bookings schema) ---
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute(
                """
                INSERT INTO tbl_bookings (
                    customer_id,
                    artisan_id,
                    booking_date,
                    service_address,
                    agreed_amount,
                    booking_status,
                    customer_notes,
                    created_at,
                    updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                """,
                (
                    customer_id,
                    artisan_id,
                    booking_datetime,
                    address,
                    estimated_price,
                    'pending',
                    description
                )
            )
            connection.commit()
            booking_id = cursor.lastrowid

        return construct_response(HTTP_OK, {
            "success": True,
            "message": "Booking created successfully.",
            "booking": {
                "booking_id": booking_id,
                "customer_id": customer_id,
                "artisan_id": artisan_id,
                "artisan_name": f"{artisan['first_name']} {artisan['last_name']}",
                "booking_date": booking_date,
                "booking_time": booking_time,
                "service_address": address,
                "agreed_amount": estimated_price,
                "booking_status": "pending",
                "customer_notes": description
            }
        })

    except json.JSONDecodeError:
        return construct_response(HTTP_BAD_REQUEST, {
            "success": False,
            "message": "Invalid JSON in request body."
        })

    except Exception as e:
        logger.exception("createBooking failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error."
        })

def getCustomerBookings(event, context):
    """
    Get all bookings for the authenticated customer.
    Uses LEFT JOIN on tbl_job_requests so bookings without a job_request_id still appear.
    """
    try:
        claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
        cognito_sub = claims["sub"]

        connection.ping(reconnect=True)

        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            cursor.execute(
                """
                SELECT user_id
                FROM tbl_users
                WHERE cognito_sub = %s
                LIMIT 1
                """,
                (cognito_sub,)
            )

            customer = cursor.fetchone()

            if not customer:
                return construct_response(HTTP_NOT_FOUND, {
                    "success": False,
                    "message": "Authenticated customer not found."
                })

            customer_id = customer["user_id"]

            cursor.execute(
                """
                SELECT
                    b.booking_id,
                    b.job_request_id,
                    b.artisan_id,
                    b.booking_date,
                    b.service_address,
                    b.agreed_amount,
                    b.booking_status,
                    b.customer_notes,
                    b.artisan_notes,
                    b.created_at,
                    jr.title AS job_title,
                    jr.description AS job_description,
                    u.first_name AS artisan_first_name,
                    u.last_name AS artisan_last_name,
                    u.phone_number AS artisan_phone
                FROM tbl_bookings b
                LEFT JOIN tbl_job_requests jr ON jr.job_request_id = b.job_request_id
                JOIN tbl_users u ON u.user_id = b.artisan_id
                WHERE b.customer_id = %s
                ORDER BY b.created_at DESC
                """,
                (customer_id,)
            )

            bookings = cursor.fetchall()

        return construct_response(HTTP_OK, {
            "success": True,
            "customerId": customer_id,
            "total": len(bookings),
            "bookings": bookings,
            "message": "Bookings retrieved successfully."
        })

    except Exception as e:
        logger.exception("getCustomerBookings failed")

        try:
            connection.rollback()
        except:
            pass

        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error."
        })

def createReview(event, context):

    try:

        claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
        cognito_sub = claims["sub"]

        body = event.get("body")

        if isinstance(body, str):
            body = json.loads(body)

        required_fields = [
            "bookingId",
            "rating"
        ]

        missing_fields = [
            field for field in required_fields
            if not body.get(field)
        ]

        if missing_fields:
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "success": False,
                    "message": f"Missing required fields: {', '.join(missing_fields)}"
                })
            }

        rating = body.get("rating")

        if not isinstance(rating, int) or rating < 1 or rating > 5:
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "success": False,
                    "message": "Rating must be a number between 1 and 5."
                })
            }

        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            # get customer
            cursor.execute(
                """
                SELECT user_id
                FROM tbl_users
                WHERE cognito_sub = %s
                LIMIT 1
                """,
                (cognito_sub,)
            )

            customer = cursor.fetchone()

            if not customer:
                return {
                    "statusCode": 404,
                    "body": json.dumps({
                        "success": False,
                        "message": "Customer not found."
                    })
                }

            customer_id = customer["user_id"]

            # get booking
            cursor.execute(
                """
                SELECT
                    b.booking_id,
                    b.job_request_id,
                    b.artisan_id,
                    b.customer_id,
                    b.booking_status
                FROM tbl_bookings b
                WHERE b.booking_id = %s
                LIMIT 1
                """,
                (body["bookingId"],)
            )

            booking = cursor.fetchone()

            if not booking:
                return {
                    "statusCode": 404,
                    "body": json.dumps({
                        "success": False,
                        "message": "Booking not found."
                    })
                }

            # only the customer who made the booking can review
            if booking["customer_id"] != customer_id:
                return {
                    "statusCode": 403,
                    "body": json.dumps({
                        "success": False,
                        "message": "You are not authorized to review this booking."
                    })
                }

            # booking must be completed before reviewing
            if booking["booking_status"] != "completed":
                return {
                    "statusCode": 400,
                    "body": json.dumps({
                        "success": False,
                        "message": "You can only review a completed booking."
                    })
                }

            # check if review already exists
            cursor.execute(
                """
                SELECT review_id
                FROM tbl_reviews
                WHERE booking_id = %s
                LIMIT 1
                """,
                (body["bookingId"],)
            )

            existing_review = cursor.fetchone()

            if existing_review:
                return {
                    "statusCode": 409,
                    "body": json.dumps({
                        "success": False,
                        "message": "You have already reviewed this booking."
                    })
                }

            # insert review
            cursor.execute(
                """
                INSERT INTO tbl_reviews
                (
                    booking_id,
                    job_request_id,
                    customer_id,
                    artisan_id,
                    rating,
                    review_text
                )
                VALUES
                (%s,%s,%s,%s,%s,%s)
                """,
                (
                    body["bookingId"],
                    booking["job_request_id"],
                    customer_id,
                    booking["artisan_id"],
                    rating,
                    body.get("reviewText")
                )
            )

            review_id = cursor.lastrowid

            # update artisan average rating
            cursor.execute(
                """
                UPDATE tbl_artisans
                SET
                    average_rating = (
                        SELECT AVG(rating)
                        FROM tbl_reviews
                        WHERE artisan_id = %s
                    ),
                    total_reviews = (
                        SELECT COUNT(*)
                        FROM tbl_reviews
                        WHERE artisan_id = %s
                    )
                WHERE user_id = %s
                """,
                (
                    booking["artisan_id"],
                    booking["artisan_id"],
                    booking["artisan_id"]
                )
            )

        connection.commit()

        return {
            "statusCode": 201,
            "body": json.dumps({
                "success": True,
                "reviewId": review_id,
                "bookingId": body["bookingId"],
                "rating": rating,
                "message": "Review submitted successfully."
            })
        }

    except Exception as e:

        try:
            connection.rollback()
        except:
            pass

        return {
            "statusCode": 500,
            "body": json.dumps({
                "success": False,
                "message": "Internal server error.",
                "error": str(e)
            })
        }

def construct_response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
        },
        "body": json.dumps(body, default=str)
    }


def searchNearbyArtisans(event, context):
    """
    Search for verified, available artisans near a customer's location
    who offer ANY service within a given category (list of service ids).

    Request body (POST):
      - latitude (float): Customer's latitude (required)
      - longitude (float): Customer's longitude (required)
      - serviceIds (list[int]): The services to search for (required)
            e.g. [51,52,53,54,55] for "Electrician"
      - serviceId (int): Backward-compatible single-id alternative to serviceIds
      - radius (float): Search radius in km (optional, default: 10)
      - limit (int): Max results (optional, default: 20)
      - sortBy (str): "nearest" | "top_rated" | "most_experienced" (optional, default: "nearest")
    """
    try:
        # --- Auth: extract user from Cognito JWT ---
        claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
        cognito_sub = claims["sub"]

        connection.ping(reconnect=True)

        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute(
                """
                SELECT user_id, role, is_active
                FROM tbl_users
                WHERE cognito_sub = %s
                LIMIT 1
                """,
                (cognito_sub,)
            )
            user = cursor.fetchone()

        if not user:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Authenticated user not found."
            })

        if user["role"].lower() != "customer":
            return construct_response(HTTP_FORBIDDEN, {
                "success": False,
                "message": "Only customers can search for artisans."
            })

        if user["is_active"] != 1:
            return construct_response(HTTP_FORBIDDEN, {
                "success": False,
                "message": "Your account is inactive."
            })

        # --- Parse & validate request body ---
        body = event.get("body")
        if isinstance(body, str):
            body = json.loads(body)
        if body is None:
            body = {}

        required_fields = ["latitude", "longitude"]
        missing_fields = [f for f in required_fields if body.get(f) is None]
        if missing_fields:
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": f"Missing required fields: {', '.join(missing_fields)}"
            })

        latitude = float(body["latitude"])
        longitude = float(body["longitude"])

        # Accept either serviceIds (list) or serviceId (single, backward compatible)
        raw_service_ids = body.get("serviceIds")
        if not raw_service_ids:
            single = body.get("serviceId")
            raw_service_ids = [single] if single is not None else []

        if not raw_service_ids:
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": "serviceIds is required."
            })

        try:
            service_ids = [int(sid) for sid in raw_service_ids]
        except (TypeError, ValueError):
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": "serviceIds must be a list of integers."
            })

        radius = float(body.get("radius", 10))
        limit = int(body.get("limit", 20))
        sort_by = body.get("sortBy", "nearest")

        # Validate coordinates
        if not (-90 <= latitude <= 90):
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": "Latitude must be between -90 and 90."
            })
        if not (-180 <= longitude <= 180):
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": "Longitude must be between -180 and 180."
            })

        # --- Build sort clause ---
        sort_clauses = {
            "nearest": "distance ASC, average_rating DESC",
            "top_rated": "average_rating DESC, total_reviews DESC, distance ASC",
            "most_experienced": "years_of_experience DESC, average_rating DESC, distance ASC"
        }
        order_by = sort_clauses.get(sort_by, sort_clauses["nearest"])

        placeholders = ",".join(["%s"] * len(service_ids))

        # --- Query nearby artisans ---
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:
            sql = f"""
                SELECT * FROM (
                    SELECT
                        a.artisan_id,
                        a.business_name,
                        a.years_of_experience,
                        a.average_rating,
                        a.total_reviews,
                        u.first_name,
                        u.last_name,
                        u.phone_number,
                        ad.label AS address_label,
                        ad.address,
                        ad.city,
                        ad.state,
                        ad.latitude AS artisan_latitude,
                        ad.longitude AS artisan_longitude,
                        s.id AS service_id,
                        s.name AS service_name,
                        s.base_price,
                        ats.custom_price,
                        ats.estimated_duration,
                        (
                            ST_Distance_Sphere(
                                POINT(ad.longitude, ad.latitude),
                                POINT(%s, %s)
                            ) / 1000
                        ) AS distance,
                        ROW_NUMBER() OVER (
                            PARTITION BY a.artisan_id
                            ORDER BY (
                                ST_Distance_Sphere(
                                    POINT(ad.longitude, ad.latitude),
                                    POINT(%s, %s)
                                )
                            ) ASC
                        ) AS rn
                    FROM tbl_artisans a
                    INNER JOIN tbl_users u
                        ON u.user_id = a.user_id
                    INNER JOIN tbl_addresses ad
                        ON ad.user_id = u.user_id
                        AND ad.latitude IS NOT NULL
                    INNER JOIN tbl_artisan_services ats
                        ON ats.artisan_id = a.artisan_id
                    INNER JOIN services s
                        ON s.id = ats.service_id
                    WHERE
                        ats.service_id IN ({placeholders})
                        AND ats.is_active = 1
                        AND a.is_available = 1
                        AND a.verification_status = 'verified'
                        AND u.is_active = 1
                ) AS results
                WHERE rn = 1
                  AND distance <= %s
                ORDER BY {order_by}
                LIMIT %s
            """

            cursor.execute(sql, (
                longitude, latitude,
                longitude, latitude,
                *service_ids,
                radius,
                limit
            ))

            artisans = cursor.fetchall()

        # Convert Decimal fields to float for JSON serialization
        for artisan in artisans:
            artisan.pop("rn", None)
            if artisan.get("distance") is not None:
                artisan["distance"] = round(float(artisan["distance"]), 2)
            if artisan.get("average_rating") is not None:
                artisan["average_rating"] = float(artisan["average_rating"])
            if artisan.get("base_price") is not None:
                artisan["base_price"] = float(artisan["base_price"])
            if artisan.get("custom_price") is not None:
                artisan["custom_price"] = float(artisan["custom_price"])

        return construct_response(HTTP_OK, {
            "success": True,
            "customer_id": user["user_id"],
            "service_ids": service_ids,
            "sort_by": sort_by,
            "radius_km": radius,
            "count": len(artisans),
            "artisans": artisans
        })

    except ValueError:
        return construct_response(HTTP_BAD_REQUEST, {
            "success": False,
            "message": "latitude, longitude, radius, limit and serviceIds must be numeric."
        })

    except json.JSONDecodeError:
        return construct_response(HTTP_BAD_REQUEST, {
            "success": False,
            "message": "Invalid JSON in request body."
        })

    except Exception as e:
        logger.exception("searchNearbyArtisans failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error."
        })


def updateArtisanAvailability(event, context):
    """
    POST /updateArtisanAvailability

    Body:
    {
        "artisan_id": 1,
        "slots": [
            {
                "day_of_week": "monday",
                "start_time": "09:00",
                "end_time": "17:00",
                "is_available": true
            },
            {
                "day_of_week": "tuesday",
                "start_time": "10:00",
                "end_time": "16:00",
                "is_available": true
            }
        ]
    }

    Replaces all existing availability for the artisan with the new slots.
    """
    try:
        body = parse_body(event)
        artisan_id = body.get("artisan_id")
        slots = body.get("slots", [])

        if not artisan_id:
            return construct_response(HTTP_BAD_REQUEST, {
                "error": "artisan_id is required"
            })

        if not slots or not isinstance(slots, list):
            return construct_response(HTTP_BAD_REQUEST, {
                "error": "slots must be a non-empty array"
            })

        valid_days = ['monday', 'tuesday', 'wednesday', 'thursday',
                      'friday', 'saturday', 'sunday']

        # Validate each slot
        for slot in slots:
            day = slot.get("day_of_week", "").lower()
            if day not in valid_days:
                return construct_response(HTTP_BAD_REQUEST, {
                    "error": f"Invalid day_of_week: '{slot.get('day_of_week')}'. "
                             f"Must be one of: {', '.join(valid_days)}"
                })
            if not slot.get("start_time") or not slot.get("end_time"):
                return construct_response(HTTP_BAD_REQUEST, {
                    "error": "Each slot must have start_time and end_time (HH:MM format)"
                })

        cursor = connection.cursor()

        try:
            # Delete existing availability for this artisan
            delete_query = "DELETE FROM tbl_artisan_availability WHERE artisan_id = %s"
            cursor.execute(delete_query, (artisan_id,))

            # Insert new slots
            insert_query = """
                INSERT INTO tbl_artisan_availability (
                    artisan_id, day_of_week, start_time,
                    end_time, is_available, created_at, updated_at
                ) VALUES (
                    %s, %s, %s,
                    %s, %s, %s, %s
                )
            """

            now = datetime.now()
            inserted_count = 0

            for slot in slots:
                params = (
                    artisan_id,
                    slot["day_of_week"].lower(),
                    slot["start_time"],
                    slot["end_time"],
                    slot.get("is_available", True),
                    now,
                    now
                )
                cursor.execute(insert_query, params)
                inserted_count += 1

            connection.commit()
            cursor.close()

            return construct_response(HTTP_OK, {
                "message": "Availability updated successfully",
                "artisan_id": artisan_id,
                "slots_saved": inserted_count
            })

        except Exception as e:
            connection.rollback()
            cursor.close()
            raise e

    except ValueError as ve:
        return construct_response(HTTP_BAD_REQUEST, {
            "error": str(ve)
        })
    except Exception as e:
        logger.error(f"Error updating artisan availability: {str(e)}")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "error": "Failed to update artisan availability",
            "details": str(e)
        })


def getDashboard(event, context):
    """
    GET /artisan/dashboard
    Returns: profile summary, wallet, earnings, job stats, recent activity
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        artisan_id = artisan["artisan_id"]
        today = datetime.utcnow().date()
        week_start = today - timedelta(days=today.weekday())  # Monday
        month_start = today.replace(day=1)

        connection.ping(reconnect=True)
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            # ---- Wallet Balance ----
            cursor.execute("""
                SELECT COALESCE(available_balance, 0) AS available_balance,
                       COALESCE(pending_balance, 0) AS pending_balance,
                       COALESCE(total_withdrawn, 0) AS total_withdrawn
                FROM tbl_wallets
                WHERE artisan_id = %s
            """, (artisan_id,))
            wallet = cursor.fetchone() or {
                "available_balance": 0, "pending_balance": 0, "total_withdrawn": 0
            }

            # ---- Earnings Today ----
            cursor.execute("""
                SELECT COALESCE(SUM(net_amount), 0) AS total
                FROM tbl_payments
                WHERE artisan_id = %s
                  AND status = 'successful'
                  AND DATE(paid_at) = %s
            """, (artisan_id, today))
            earnings_today = cursor.fetchone()["total"]

            # ---- Earnings This Week ----
            cursor.execute("""
                SELECT COALESCE(SUM(net_amount), 0) AS total
                FROM tbl_payments
                WHERE artisan_id = %s
                  AND status = 'successful'
                  AND paid_at >= %s
            """, (artisan_id, week_start))
            earnings_week = cursor.fetchone()["total"]

            # ---- Earnings This Month ----
            cursor.execute("""
                SELECT COALESCE(SUM(net_amount), 0) AS total
                FROM tbl_payments
                WHERE artisan_id = %s
                  AND status = 'successful'
                  AND paid_at >= %s
            """, (artisan_id, month_start))
            earnings_month = cursor.fetchone()["total"]

            # ---- Weekly Breakdown (by day) ----
            cursor.execute("""
                SELECT DATE(paid_at) AS date,
                       DAYNAME(paid_at) AS day_name,
                       COALESCE(SUM(net_amount), 0) AS total
                FROM tbl_payments
                WHERE artisan_id = %s
                  AND status = 'successful'
                  AND paid_at >= %s
                GROUP BY DATE(paid_at), DAYNAME(paid_at)
                ORDER BY DATE(paid_at)
            """, (artisan_id, week_start))
            weekly_breakdown = cursor.fetchall()

            # ---- Job Stats (from both job_requests and bookings) ----
            cursor.execute("""
                SELECT
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_requests,
                    SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END) AS accepted_requests,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed_from_requests
                FROM tbl_job_requests
                WHERE artisan_id = %s
            """, (artisan_id,))
            request_stats = cursor.fetchone()

            cursor.execute("""
                SELECT
                    SUM(CASE WHEN booking_status = 'pending' THEN 1 ELSE 0 END) AS pending_bookings,
                    SUM(CASE WHEN booking_status = 'confirmed' THEN 1 ELSE 0 END) AS confirmed_bookings,
                    SUM(CASE WHEN booking_status = 'in_progress' THEN 1 ELSE 0 END) AS active_jobs,
                    SUM(CASE WHEN booking_status = 'completed' THEN 1 ELSE 0 END) AS completed_bookings,
                    SUM(CASE WHEN booking_status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled_jobs
                FROM tbl_bookings
                WHERE artisan_id = %s
            """, (artisan_id,))
            booking_stats = cursor.fetchone()

            # Calculate total completed jobs from both tables
            completed_from_requests = int(request_stats["completed_from_requests"] or 0)
            completed_from_bookings = int(booking_stats["completed_bookings"] or 0)
            total_completed = completed_from_requests + completed_from_bookings

            # ---- Completion Rate ----
            cursor.execute("""
                SELECT COUNT(*) AS total_jobs
                FROM tbl_job_requests
                WHERE artisan_id = %s
                  AND status IN ('completed', 'accepted', 'in_progress', 'cancelled')
            """, (artisan_id,))
            total_jobs = cursor.fetchone()["total_jobs"]
            completion_rate = round((total_completed / total_jobs * 100), 1) if total_jobs > 0 else 0

            # ---- Response Rate & Avg Response Time ----
            cursor.execute("""
                SELECT 
                    COUNT(*) AS total_requests,
                    SUM(CASE WHEN status IN ('accepted', 'completed', 'in_progress') THEN 1 ELSE 0 END) AS responded,
                    AVG(TIMESTAMPDIFF(MINUTE, created_at, updated_at)) AS avg_response_minutes
                FROM tbl_job_requests
                WHERE artisan_id = %s
                  AND status != 'pending'
            """, (artisan_id,))
            response_data = cursor.fetchone()
            total_requests = int(response_data["total_requests"] or 0)
            responded = int(response_data["responded"] or 0)
            response_rate = round((responded / total_requests * 100), 1) if total_requests > 0 else 0
            avg_response_time = int(response_data["avg_response_minutes"] or 0)

            # ---- Upcoming Bookings (next 5) ----
            cursor.execute("""
                SELECT b.booking_id, b.booking_date, b.service_address,
                       b.agreed_amount, b.booking_status, b.customer_notes,
                       u.first_name AS customer_first_name,
                       u.last_name AS customer_last_name,
                       u.phone_number AS customer_phone
                FROM tbl_bookings b
                INNER JOIN tbl_users u ON u.user_id = b.customer_id
                WHERE b.artisan_id = %s
                  AND b.booking_status IN ('pending', 'confirmed')
                  AND b.booking_date >= %s
                ORDER BY b.booking_date ASC
                LIMIT 5
            """, (artisan_id, today))
            upcoming_bookings = cursor.fetchall()

            # ---- Recent Job Requests (latest 5 pending) ----
            cursor.execute("""
                SELECT jr.job_request_id, jr.title, jr.description,
                       jr.location_address, jr.preferred_date, jr.status,
                       jr.created_at,
                       u.first_name AS customer_first_name,
                       u.last_name AS customer_last_name
                FROM tbl_job_requests jr
                INNER JOIN tbl_users u ON u.user_id = jr.customer_id
                WHERE jr.artisan_id = %s
                  AND jr.status = 'pending'
                ORDER BY jr.created_at DESC
                LIMIT 5
            """, (artisan_id,))
            pending_requests = cursor.fetchall()

            # ---- Recent Reviews (latest 3) ----
            cursor.execute("""
                SELECT r.review_id, r.rating, r.review_text, r.created_at,
                       u.first_name AS customer_first_name,
                       u.last_name AS customer_last_name
                FROM tbl_reviews r
                INNER JOIN tbl_users u ON u.user_id = r.customer_id
                WHERE r.artisan_id = %s
                ORDER BY r.created_at DESC
                LIMIT 3
            """, (artisan_id,))
            recent_reviews = cursor.fetchall()

            # ---- Unread Notifications Count ----
            cursor.execute("""
                SELECT COUNT(*) AS count
                FROM tbl_notifications
                WHERE artisan_id = %s AND is_read = 0
            """, (artisan_id,))
            unread_notifications = cursor.fetchone()["count"]

        # ---- Build Response ----
        return construct_response(HTTP_OK, {
            "success": True,
            "data": {
                "profile": {
                    "artisan_id": artisan["artisan_id"],
                    "first_name": artisan["first_name"],
                    "last_name": artisan["last_name"],
                    "business_name": artisan["business_name"],
                    "average_rating": float(artisan["average_rating"] or 0),
                    "total_reviews": artisan["total_reviews"],
                    "is_available": bool(artisan["is_available"]),
                    "verification_status": artisan["verification_status"]
                },
                "wallet": {
                    "available_balance": float(wallet["available_balance"]),
                    "pending_balance": float(wallet["pending_balance"]),
                    "total_withdrawn": float(wallet["total_withdrawn"])
                },
                "earnings": {
                    "today": float(earnings_today),
                    "this_week": float(earnings_week),
                    "this_month": float(earnings_month),
                    "weekly_breakdown": weekly_breakdown
                },
                "jobs": {
                    "pending_requests": int(request_stats["pending_requests"] or 0),
                    "accepted_requests": int(request_stats["accepted_requests"] or 0),
                    "pending_bookings": int(booking_stats["pending_bookings"] or 0),
                    "confirmed_bookings": int(booking_stats["confirmed_bookings"] or 0),
                    "active_jobs": int(booking_stats["active_jobs"] or 0),
                    "completed_jobs": total_completed,
                    "cancelled_jobs": int(booking_stats["cancelled_jobs"] or 0),
                    "completion_rate": completion_rate
                },
                "response": {
                    "response_rate": response_rate,
                    "avg_response_time_minutes": avg_response_time
                },
                "upcoming_bookings": upcoming_bookings,
                "pending_requests": pending_requests,
                "recent_reviews": recent_reviews,
                "unread_notifications": unread_notifications
            }
        })

    except Exception as e:
        logger.exception("getDashboard failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })


# ============================================================
# 2. PUT /artisan/toggle-availability
#    Toggle artisan online/offline status
# ============================================================

def toggleAvailability(event, context):
    """
    PUT /artisan/toggle-availability
    Body: { "is_available": true/false }
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        body = parse_body(event)
        is_available = body.get("is_available")

        if is_available is None:
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": "is_available (true/false) is required."
            })

        new_status = 1 if is_available else 0

        connection.ping(reconnect=True)
        with connection.cursor() as cursor:
            cursor.execute("""
                UPDATE tbl_artisans
                SET is_available = %s, updated_at = NOW()
                WHERE artisan_id = %s
            """, (new_status, artisan["artisan_id"]))
            connection.commit()

        return construct_response(HTTP_OK, {
            "success": True,
            "message": f"Availability set to {'available' if new_status else 'offline'}.",
            "is_available": bool(new_status)
        })

    except Exception as e:
        logger.exception("toggleAvailability failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })


# ============================================================
# 3. GET /artisan/earnings
#    Detailed earnings with filters
# ============================================================


def getEarnings(event, context):
    """
    GET /artisan/earnings?period=week|month|year|all&page=1&limit=20
    Returns: earnings summary + transaction history
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        artisan_id = artisan["artisan_id"]
        params = event.get("queryStringParameters") or {}
        period = params.get("period", "week")
        page = max(int(params.get("page", 1)), 1)
        limit = min(int(params.get("limit", 20)), 100)
        offset = (page - 1) * limit

        today = datetime.utcnow().date()

        # Determine date filter
        if period == "today":
            date_filter = today
        elif period == "week":
            date_filter = today - timedelta(days=today.weekday())
        elif period == "month":
            date_filter = today.replace(day=1)
        elif period == "year":
            date_filter = today.replace(month=1, day=1)
        else:
            date_filter = None  # all time

        connection.ping(reconnect=True)
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            # Total earnings for period
            if date_filter:
                cursor.execute("""
                    SELECT COALESCE(SUM(net_amount), 0) AS total_earnings,
                           COUNT(*) AS total_transactions
                    FROM tbl_payments
                    WHERE artisan_id = %s AND status = 'successful' AND paid_at >= %s
                """, (artisan_id, date_filter))
            else:
                cursor.execute("""
                    SELECT COALESCE(SUM(net_amount), 0) AS total_earnings,
                           COUNT(*) AS total_transactions
                    FROM tbl_payments
                    WHERE artisan_id = %s AND status = 'successful'
                """, (artisan_id,))

            summary = cursor.fetchone()

            # Transaction list (paginated)
            if date_filter:
                cursor.execute("""
                    SELECT p.payment_id, p.amount, p.net_amount,
                           (p.amount - p.net_amount) AS platform_fee,
                           p.payment_method, p.payment_provider,
                           p.payment_reference, p.status, p.paid_at,
                           jr.job_request_id, jr.title AS job_title,
                           jr.description AS job_description,
                           u.first_name AS customer_first_name,
                           u.last_name AS customer_last_name
                    FROM tbl_payments p
                    LEFT JOIN tbl_job_requests jr ON jr.job_request_id = p.job_request_id
                    LEFT JOIN tbl_users u ON u.user_id = p.payer_user_id
                    WHERE p.artisan_id = %s AND p.status = 'successful' AND p.paid_at >= %s
                    ORDER BY p.paid_at DESC
                    LIMIT %s OFFSET %s
                """, (artisan_id, date_filter, limit, offset))
            else:
                cursor.execute("""
                    SELECT p.payment_id, p.amount, p.net_amount,
                           (p.amount - p.net_amount) AS platform_fee,
                           p.payment_method, p.payment_provider,
                           p.payment_reference, p.status, p.paid_at,
                           jr.job_request_id, jr.title AS job_title,
                           jr.description AS job_description,
                           u.first_name AS customer_first_name,
                           u.last_name AS customer_last_name
                    FROM tbl_payments p
                    LEFT JOIN tbl_job_requests jr ON jr.job_request_id = p.job_request_id
                    LEFT JOIN tbl_users u ON u.user_id = p.payer_user_id
                    WHERE p.artisan_id = %s AND p.status = 'successful'
                    ORDER BY p.paid_at DESC
                    LIMIT %s OFFSET %s
                """, (artisan_id, limit, offset))

            transactions = cursor.fetchall()

            # Wallet balance
            cursor.execute("""
                SELECT COALESCE(available_balance, 0) AS available_balance,
                       COALESCE(pending_balance, 0) AS pending_balance
                FROM tbl_wallets WHERE artisan_id = %s
            """, (artisan_id,))
            wallet = cursor.fetchone() or {"available_balance": 0, "pending_balance": 0}

        return construct_response(HTTP_OK, {
            "success": True,
            "data": {
                "period": period,
                "total_earnings": float(summary["total_earnings"]),
                "total_transactions": summary["total_transactions"],
                "wallet_balance": float(wallet["available_balance"]),
                "pending_balance": float(wallet["pending_balance"]),
                "transactions": transactions,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": summary["total_transactions"]
                }
            }
        })

    except Exception as e:
        logger.exception("getEarnings failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })



def getJobs(event, context):
    """
    GET /artisan/jobs?status=pending|confirmed|in_progress|completed|cancelled&page=1&limit=20
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        artisan_id = artisan["artisan_id"]
        params = event.get("queryStringParameters") or {}
        status_filter = params.get("status")
        page = max(int(params.get("page", 1)), 1)
        limit = min(int(params.get("limit", 20)), 100)
        offset = (page - 1) * limit

        connection.ping(reconnect=True)
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            # Build query
            base_query = """
                SELECT b.booking_id, b.job_request_id, b.booking_date,
                       b.service_address, b.agreed_amount, b.booking_status,
                       b.customer_notes, b.artisan_notes, b.created_at,
                       u.first_name AS customer_first_name,
                       u.last_name AS customer_last_name,
                       u.phone_number AS customer_phone
                FROM tbl_bookings b
                INNER JOIN tbl_users u ON u.user_id = b.customer_id
                WHERE b.artisan_id = %s
            """
            query_params = [artisan_id]

            if status_filter:
                base_query += " AND b.booking_status = %s"
                query_params.append(status_filter)

            # Count total
            count_query = f"SELECT COUNT(*) AS total FROM ({base_query}) AS sub"
            cursor.execute(count_query, query_params)
            total = cursor.fetchone()["total"]

            # Fetch page
            base_query += " ORDER BY b.created_at DESC LIMIT %s OFFSET %s"
            query_params.extend([limit, offset])
            cursor.execute(base_query, query_params)
            bookings = cursor.fetchall()

        return construct_response(HTTP_OK, {
            "success": True,
            "data": {
                "bookings": bookings,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total
                }
            }
        })

    except Exception as e:
        logger.exception("getJobs failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })


# ============================================================
# 5. GET /artisan/job-requests
#    Pending job requests for the artisan
# ============================================================

def getJobRequests(event, context):
    """
    GET /artisan/job-requests?status=pending|accepted|declined&page=1&limit=20
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        artisan_id = artisan["artisan_id"]
        params = event.get("queryStringParameters") or {}
        status_filter = params.get("status", "pending")
        page = max(int(params.get("page", 1)), 1)
        limit = min(int(params.get("limit", 20)), 100)
        offset = (page - 1) * limit

        connection.ping(reconnect=True)
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            cursor.execute("""
                SELECT COUNT(*) AS total
                FROM tbl_job_requests
                WHERE artisan_id = %s AND status = %s
            """, (artisan_id, status_filter))
            total = cursor.fetchone()["total"]

            cursor.execute("""
                SELECT jr.job_request_id, jr.customer_id, jr.service_id,
                       jr.title, jr.description, jr.location_address,
                       jr.preferred_date, jr.status, jr.created_at,
                       u.first_name AS customer_first_name,
                       u.last_name AS customer_last_name,
                       u.phone_number AS customer_phone,
                       s.name AS service_name
                FROM tbl_job_requests jr
                INNER JOIN tbl_users u ON u.user_id = jr.customer_id
                LEFT JOIN services s ON s.id = jr.service_id
                WHERE jr.artisan_id = %s AND jr.status = %s
                ORDER BY jr.created_at DESC
                LIMIT %s OFFSET %s
            """, (artisan_id, status_filter, limit, offset))
            requests = cursor.fetchall()

        return construct_response(HTTP_OK, {
            "success": True,
            "data": {
                "requests": requests,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total
                }
            }
        })

    except Exception as e:
        logger.exception("getJobRequests failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })


# ============================================================
# 6. PUT /artisan/job-requests/{jobRequestId}/respond
#    Accept or decline a job request
# ============================================================

def respondToJobRequest(event, context):
    """
    PUT /artisan/job-requests/{jobRequestId}/respond
    Body: { "status": "accepted" | "declined" }
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        artisan_id = artisan["artisan_id"]
        path_params = event.get("pathParameters") or {}
        job_request_id = path_params.get("jobRequestId")

        if not job_request_id:
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": "jobRequestId is required in path."
            })

        body = parse_body(event)
        status = body.get("status")

        if status not in ["accepted", "declined"]:
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": "Status must be 'accepted' or 'declined'."
            })

        connection.ping(reconnect=True)
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            # Verify request belongs to this artisan and is pending
            cursor.execute("""
                SELECT job_request_id, customer_id, service_id, title,
                       description, location_address, preferred_date, status
                FROM tbl_job_requests
                WHERE job_request_id = %s AND artisan_id = %s
                LIMIT 1
            """, (job_request_id, artisan_id))
            job_request = cursor.fetchone()

            if not job_request:
                return construct_response(HTTP_NOT_FOUND, {
                    "success": False,
                    "message": "Job request not found."
                })

            if job_request["status"] != "pending":
                return construct_response(HTTP_BAD_REQUEST, {
                    "success": False,
                    "message": "This job request has already been processed."
                })

            if status == "accepted":
                # Update request status
                cursor.execute("""
                    UPDATE tbl_job_requests
                    SET status = 'accepted', updated_at = NOW()
                    WHERE job_request_id = %s
                """, (job_request_id,))

                # Auto-create booking from accepted request
                cursor.execute("""
                    INSERT INTO tbl_bookings (
                        customer_id, artisan_id, job_request_id,
                        booking_date, service_address, booking_status,
                        customer_notes, created_at, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, 'confirmed', %s, NOW(), NOW())
                """, (
                    job_request["customer_id"],
                    artisan_id,
                    job_request_id,
                    job_request["preferred_date"],
                    job_request["location_address"],
                    job_request["description"]
                ))
                booking_id = cursor.lastrowid

                connection.commit()

                return construct_response(HTTP_OK, {
                    "success": True,
                    "message": "Job request accepted. Booking created.",
                    "job_request_id": int(job_request_id),
                    "booking_id": booking_id,
                    "status": "accepted"
                })

            else:
                # Decline
                cursor.execute("""
                    UPDATE tbl_job_requests
                    SET status = 'declined', updated_at = NOW()
                    WHERE job_request_id = %s
                """, (job_request_id,))
                connection.commit()

                return construct_response(HTTP_OK, {
                    "success": True,
                    "message": "Job request declined.",
                    "job_request_id": int(job_request_id),
                    "status": "declined"
                })

    except Exception as e:
        try:
            connection.rollback()
        except:
            pass
        logger.exception("respondToJobRequest failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })


# ============================================================
# 7. GET /artisan/reviews
#    All reviews for the artisan
# ============================================================

def getReviews(event, context):
    """
    GET /artisan/reviews?page=1&limit=20
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        artisan_id = artisan["artisan_id"]
        params = event.get("queryStringParameters") or {}
        page = max(int(params.get("page", 1)), 1)
        limit = min(int(params.get("limit", 20)), 100)
        offset = (page - 1) * limit

        connection.ping(reconnect=True)
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            cursor.execute("""
                SELECT COUNT(*) AS total FROM tbl_reviews WHERE artisan_id = %s
            """, (artisan_id,))
            total = cursor.fetchone()["total"]

            cursor.execute("""
                SELECT r.review_id, r.booking_id, r.rating, r.review_text,
                       r.created_at,
                       u.first_name AS customer_first_name,
                       u.last_name AS customer_last_name
                FROM tbl_reviews r
                INNER JOIN tbl_users u ON u.user_id = r.customer_id
                WHERE r.artisan_id = %s
                ORDER BY r.created_at DESC
                LIMIT %s OFFSET %s
            """, (artisan_id, limit, offset))
            reviews = cursor.fetchall()

            # Rating breakdown
            cursor.execute("""
                SELECT rating, COUNT(*) AS count
                FROM tbl_reviews
                WHERE artisan_id = %s
                GROUP BY rating
                ORDER BY rating DESC
            """, (artisan_id,))
            rating_breakdown = cursor.fetchall()

        return construct_response(HTTP_OK, {
            "success": True,
            "data": {
                "average_rating": float(artisan["average_rating"] or 0),
                "total_reviews": artisan["total_reviews"],
                "rating_breakdown": rating_breakdown,
                "reviews": reviews,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total
                }
            }
        })

    except Exception as e:
        logger.exception("getReviews failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })


# ============================================================
# 8. GET /artisan/notifications
#    Notifications list
# ============================================================

def getNotifications(event, context):
    """
    GET /artisan/notifications?page=1&limit=30
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        artisan_id = artisan["artisan_id"]
        params = event.get("queryStringParameters") or {}
        page = max(int(params.get("page", 1)), 1)
        limit = min(int(params.get("limit", 30)), 100)
        offset = (page - 1) * limit

        connection.ping(reconnect=True)
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            cursor.execute("""
                SELECT COUNT(*) AS total FROM tbl_notifications WHERE artisan_id = %s
            """, (artisan_id,))
            total = cursor.fetchone()["total"]

            cursor.execute("""
                SELECT COUNT(*) AS unread
                FROM tbl_notifications
                WHERE artisan_id = %s AND is_read = 0
            """, (artisan_id,))
            unread = cursor.fetchone()["unread"]

            cursor.execute("""
                SELECT id, type, title, body, data, is_read, created_at
                FROM tbl_notifications
                WHERE artisan_id = %s
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """, (artisan_id, limit, offset))
            notifications = cursor.fetchall()

        return construct_response(HTTP_OK, {
            "success": True,
            "data": {
                "unread_count": unread,
                "notifications": notifications,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total
                }
            }
        })

    except Exception as e:
        logger.exception("getNotifications failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })


# ============================================================
# 9. PUT /artisan/notifications/mark-read
#    Mark notifications as read
# ============================================================

def markNotificationsRead(event, context):
    """
    PUT /artisan/notifications/mark-read
    Body: { "notification_ids": [1, 2, 3] } OR { "mark_all": true }
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        artisan_id = artisan["artisan_id"]
        body = parse_body(event)
        mark_all = body.get("mark_all", False)
        notification_ids = body.get("notification_ids", [])

        connection.ping(reconnect=True)
        with connection.cursor() as cursor:

            if mark_all:
                cursor.execute("""
                    UPDATE tbl_notifications
                    SET is_read = 1, read_at = NOW()
                    WHERE artisan_id = %s AND is_read = 0
                """, (artisan_id,))
            elif notification_ids:
                placeholders = ",".join(["%s"] * len(notification_ids))
                cursor.execute(f"""
                    UPDATE tbl_notifications
                    SET is_read = 1, read_at = NOW()
                    WHERE artisan_id = %s AND id IN ({placeholders}) AND is_read = 0
                """, (artisan_id, *notification_ids))
            else:
                return construct_response(HTTP_BAD_REQUEST, {
                    "success": False,
                    "message": "Provide notification_ids or set mark_all to true."
                })

            updated = cursor.rowcount
            connection.commit()

        return construct_response(HTTP_OK, {
            "success": True,
            "message": f"{updated} notification(s) marked as read.",
            "updated_count": updated
        })

    except Exception as e:
        logger.exception("markNotificationsRead failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })


# ============================================================
# 10. GET /artisan/profile
#     Full artisan profile
# ============================================================

def getProfile(event, context):
    """
    GET /artisan/profile
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        artisan_id = artisan["artisan_id"]

        connection.ping(reconnect=True)
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            # Full artisan details
            cursor.execute("""
                SELECT a.*, u.first_name, u.last_name, u.email, u.phone_number
                FROM tbl_artisans a
                INNER JOIN tbl_users u ON u.user_id = a.user_id
                WHERE a.artisan_id = %s
            """, (artisan_id,))
            profile = cursor.fetchone()

            # Services offered
            cursor.execute("""
                SELECT ats.id, ats.service_id, ats.custom_price,
                       ats.is_active, s.name AS service_name,
                       sc.name AS category_name
                FROM tbl_artisan_services ats
                INNER JOIN services s ON s.id = ats.service_id
                LEFT JOIN service_categories sc ON sc.id = s.category_id
                WHERE ats.artisan_id = %s
            """, (artisan_id,))
            services = cursor.fetchall()

            # Availability
            cursor.execute("""
                SELECT schedule_id, day_of_week, start_time, end_time, is_available
                FROM tbl_artisan_availability
                WHERE artisan_id = %s
                ORDER BY FIELD(day_of_week, 'Monday', 'Tuesday', 'Wednesday',
                               'Thursday', 'Friday', 'Saturday', 'Sunday')
            """, (artisan_id,))
            availability = cursor.fetchall()

            # Address
            cursor.execute("""
                SELECT address_id, label, address, city, state, latitude, longitude
                FROM tbl_addresses
                WHERE user_id = %s
                ORDER BY created_at DESC
            """, (artisan["user_id"],))
            addresses = cursor.fetchall()

        return construct_response(HTTP_OK, {
            "success": True,
            "data": {
                "profile": profile,
                "services": services,
                "availability": availability,
                "addresses": addresses
            }
        })

    except Exception as e:
        logger.exception("getProfile failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })


# ============================================================
# 11. PUT /artisan/profile
#     Update artisan profile
# ============================================================

def updateProfile(event, context):
    """
    PUT /artisan/profile
    Body: { "business_name": "...", "bio": "...", "years_of_experience": 5 }
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        body = parse_body(event)

        # Allowed fields to update
        allowed_fields = [
            "business_name", "bio", "years_of_experience"
        ]

        updates = []
        values = []
        for field in allowed_fields:
            if field in body:
                updates.append(f"{field} = %s")
                values.append(body[field])

        if not updates:
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": "No valid fields to update."
            })

        values.append(artisan["artisan_id"])

        connection.ping(reconnect=True)
        with connection.cursor() as cursor:
            cursor.execute(f"""
                UPDATE tbl_artisans
                SET {', '.join(updates)}, updated_at = NOW()
                WHERE artisan_id = %s
            """, values)
            connection.commit()

        return construct_response(HTTP_OK, {
            "success": True,
            "message": "Profile updated successfully."
        })

    except Exception as e:
        logger.exception("updateProfile failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })


# ============================================================
# 12. GET /artisan/wallet
#     Wallet balance + recent transactions
# ============================================================

def getWallet(event, context):
    """
    GET /artisan/wallet?page=1&limit=20
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        artisan_id = artisan["artisan_id"]
        params = event.get("queryStringParameters") or {}
        page = max(int(params.get("page", 1)), 1)
        limit = min(int(params.get("limit", 20)), 100)
        offset = (page - 1) * limit

        connection.ping(reconnect=True)
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            # Wallet balance
            cursor.execute("""
                SELECT wallet_id, available_balance, pending_balance,
                       total_withdrawn, currency, is_locked
                FROM tbl_wallets
                WHERE artisan_id = %s
            """, (artisan_id,))
            wallet = cursor.fetchone()

            if not wallet:
                return construct_response(HTTP_OK, {
                    "success": True,
                    "data": {
                        "wallet": {
                            "available_balance": 0,
                            "pending_balance": 0,
                            "total_withdrawn": 0,
                            "currency": "NGN"
                        },
                        "transactions": [],
                        "pagination": {"page": 1, "limit": limit, "total": 0}
                    }
                })

            # Transaction count
            cursor.execute("""
                SELECT COUNT(*) AS total
                FROM tbl_wallet_transactions
                WHERE artisan_id = %s
            """, (artisan_id,))
            total = cursor.fetchone()["total"]

            # Transactions (paginated)
            cursor.execute("""
                SELECT id, type, category, amount, balance_before,
                       balance_after, description, status, created_at
                FROM tbl_wallet_transactions
                WHERE artisan_id = %s
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """, (artisan_id, limit, offset))
            transactions = cursor.fetchall()

        return construct_response(HTTP_OK, {
            "success": True,
            "data": {
                "wallet": wallet,
                "transactions": transactions,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total
                }
            }
        })

    except Exception as e:
        logger.exception("getWallet failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })


# ============================================================
# 13. POST /artisan/wallet/withdraw
#     Request withdrawal from wallet
# ============================================================

def requestWithdrawal(event, context):
    """
    POST /artisan/wallet/withdraw
    Body: { "amount": 5000.00 }
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        artisan_id = artisan["artisan_id"]
        body = parse_body(event)
        amount = body.get("amount")

        if not amount or float(amount) <= 0:
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": "A valid positive amount is required."
            })

        amount = float(amount)
        MIN_WITHDRAWAL = 1000  # NGN

        if amount < MIN_WITHDRAWAL:
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": f"Minimum withdrawal is ₦{MIN_WITHDRAWAL:,.0f}."
            })

        connection.ping(reconnect=True)
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            # Check wallet balance
            cursor.execute("""
                SELECT wallet_id, available_balance, is_locked
                FROM tbl_wallets
                WHERE artisan_id = %s
                FOR UPDATE
            """, (artisan_id,))
            wallet = cursor.fetchone()

            if not wallet:
                return construct_response(HTTP_BAD_REQUEST, {
                    "success": False,
                    "message": "Wallet not found."
                })

            if wallet["is_locked"]:
                return construct_response(HTTP_FORBIDDEN, {
                    "success": False,
                    "message": "Your wallet is currently locked. Contact support."
                })

            available = float(wallet["available_balance"])
            if amount > available:
                return construct_response(HTTP_BAD_REQUEST, {
                    "success": False,
                    "message": f"Insufficient balance. Available: ₦{available:,.2f}"
                })

            # Debit wallet
            new_balance = available - amount
            cursor.execute("""
                UPDATE tbl_wallets
                SET available_balance = %s,
                    total_withdrawn = total_withdrawn + %s,
                    last_transaction_at = NOW(),
                    updated_at = NOW()
                WHERE artisan_id = %s
            """, (new_balance, amount, artisan_id))

            # Record transaction
            cursor.execute("""
                INSERT INTO tbl_wallet_transactions (
                    wallet_id, artisan_id, type, category, amount,
                    balance_before, balance_after, description, status, created_at
                ) VALUES (%s, %s, 'debit', 'withdrawal', %s, %s, %s,
                          'Wallet withdrawal', 'pending', NOW())
            """, (wallet["wallet_id"], artisan_id, amount, available, new_balance))

            connection.commit()

        return construct_response(HTTP_OK, {
            "success": True,
            "message": "Withdrawal request submitted.",
            "data": {
                "amount": amount,
                "new_balance": new_balance,
                "status": "pending"
            }
        })

    except Exception as e:
        try:
            connection.rollback()
        except:
            pass
        logger.exception("requestWithdrawal failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })


# ============================================================
# 14. GET /artisan/support-tickets
#     List support tickets
# ============================================================

def getSupportTickets(event, context):
    """
    GET /artisan/support-tickets?status=open|in_progress|resolved|closed&page=1&limit=20
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        artisan_id = artisan["artisan_id"]
        params = event.get("queryStringParameters") or {}
        status_filter = params.get("status")
        page = max(int(params.get("page", 1)), 1)
        limit = min(int(params.get("limit", 20)), 100)
        offset = (page - 1) * limit

        connection.ping(reconnect=True)
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            base_query = """
                FROM tbl_support_tickets
                WHERE artisan_id = %s
            """
            query_params = [artisan_id]

            if status_filter:
                base_query += " AND status = %s"
                query_params.append(status_filter)

            # Count
            cursor.execute(f"SELECT COUNT(*) AS total {base_query}", query_params)
            total = cursor.fetchone()["total"]

            # Fetch
            cursor.execute(f"""
                SELECT id, subject, description, category, priority,
                       status, created_at, resolved_at
                {base_query}
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """, (*query_params, limit, offset))
            tickets = cursor.fetchall()

        return construct_response(HTTP_OK, {
            "success": True,
            "data": {
                "tickets": tickets,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total
                }
            }
        })

    except Exception as e:
        logger.exception("getSupportTickets failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })


# ============================================================
# 15. POST /artisan/support-tickets
#     Create a new support ticket
# ============================================================

def createSupportTicket(event, context):
    """
    POST /artisan/support-tickets
    Body: { "subject": "...", "description": "...", "category": "payment", "priority": "high" }
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        body = parse_body(event)
        subject = body.get("subject", "").strip()
        description = body.get("description", "").strip()
        category = body.get("category", "general")
        priority = body.get("priority", "medium")

        if not subject or not description:
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": "subject and description are required."
            })

        valid_categories = ["general", "payment", "technical", "account", "dispute"]
        valid_priorities = ["low", "medium", "high", "urgent"]

        if category not in valid_categories:
            category = "general"
        if priority not in valid_priorities:
            priority = "medium"

        connection.ping(reconnect=True)
        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO tbl_support_tickets (
                    artisan_id, subject, description, category, priority,
                    status, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, 'open', NOW(), NOW())
            """, (artisan["artisan_id"], subject, description, category, priority))
            ticket_id = cursor.lastrowid
            connection.commit()

        return construct_response(HTTP_CREATED, {
            "success": True,
            "message": "Support ticket created.",
            "ticket_id": ticket_id
        })

    except Exception as e:
        logger.exception("createSupportTicket failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })


# ============================================================
# 16. GET /artisan/support-tickets/{ticketId}/messages
#     Get messages for a ticket
# ============================================================

def getTicketMessages(event, context):
    """
    GET /artisan/support-tickets/{ticketId}/messages
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        path_params = event.get("pathParameters") or {}
        ticket_id = path_params.get("ticketId")

        if not ticket_id:
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": "ticketId is required."
            })

        connection.ping(reconnect=True)
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            # Verify ticket belongs to artisan
            cursor.execute("""
                SELECT id, subject, status
                FROM tbl_support_tickets
                WHERE id = %s AND artisan_id = %s
            """, (ticket_id, artisan["artisan_id"]))
            ticket = cursor.fetchone()

            if not ticket:
                return construct_response(HTTP_NOT_FOUND, {
                    "success": False,
                    "message": "Ticket not found."
                })

            # Get messages
            cursor.execute("""
                SELECT id, sender_type, sender_id, message, attachments,
                       is_read, created_at
                FROM tbl_support_messages
                WHERE ticket_id = %s
                ORDER BY created_at ASC
            """, (ticket_id,))
            messages = cursor.fetchall()

            # Mark messages as read
            cursor.execute("""
                UPDATE tbl_support_messages
                SET is_read = 1
                WHERE ticket_id = %s AND sender_type != 'artisan' AND is_read = 0
            """, (ticket_id,))
            connection.commit()

        return construct_response(HTTP_OK, {
            "success": True,
            "data": {
                "ticket": ticket,
                "messages": messages
            }
        })

    except Exception as e:
        logger.exception("getTicketMessages failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })


# ============================================================
# 17. POST /artisan/support-tickets/{ticketId}/messages
#     Send a message on a ticket
# ============================================================

def sendTicketMessage(event, context):
    """
    POST /artisan/support-tickets/{ticketId}/messages
    Body: { "message": "..." }
    """
    try:
        artisan = get_artisan_from_token(event)
        if not artisan:
            return construct_response(HTTP_NOT_FOUND, {
                "success": False,
                "message": "Artisan profile not found."
            })

        path_params = event.get("pathParameters") or {}
        ticket_id = path_params.get("ticketId")
        body = parse_body(event)
        message_text = body.get("message", "").strip()

        if not ticket_id:
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": "ticketId is required."
            })

        if not message_text:
            return construct_response(HTTP_BAD_REQUEST, {
                "success": False,
                "message": "message is required."
            })

        connection.ping(reconnect=True)
        with connection.cursor(pymysql.cursors.DictCursor) as cursor:

            # Verify ticket belongs to artisan
            cursor.execute("""
                SELECT id, status FROM tbl_support_tickets
                WHERE id = %s AND artisan_id = %s
            """, (ticket_id, artisan["artisan_id"]))
            ticket = cursor.fetchone()

            if not ticket:
                return construct_response(HTTP_NOT_FOUND, {
                    "success": False,
                    "message": "Ticket not found."
                })

            if ticket["status"] == "closed":
                return construct_response(HTTP_BAD_REQUEST, {
                    "success": False,
                    "message": "Cannot send messages on a closed ticket."
                })

            # Insert message
            cursor.execute("""
                INSERT INTO tbl_support_messages (
                    ticket_id, sender_type, sender_id, message, created_at
                ) VALUES (%s, 'artisan', %s, %s, NOW())
            """, (ticket_id, artisan["artisan_id"], message_text))
            message_id = cursor.lastrowid

            # Update ticket status if it was waiting on user
            if ticket["status"] == "waiting_on_user":
                cursor.execute("""
                    UPDATE tbl_support_tickets
                    SET status = 'in_progress', updated_at = NOW()
                    WHERE id = %s
                """, (ticket_id,))

            connection.commit()

        return construct_response(HTTP_CREATED, {
            "success": True,
            "message": "Message sent.",
            "message_id": message_id
        })

    except Exception as e:
        logger.exception("sendTicketMessage failed")
        return construct_response(HTTP_INTERNAL_ERROR, {
            "success": False,
            "message": "Internal server error.",
            "error": str(e)
        })
