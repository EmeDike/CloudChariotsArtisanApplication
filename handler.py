import json
import logging
import os
from datetime import datetime

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