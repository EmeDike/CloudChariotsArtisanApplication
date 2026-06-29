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
def user_login(event, context):
    cognito_client = boto3.client(
        "cognito-idp",
        region_name=COGNITO_REGION
    )

    try:
        body = event.get("body", "{}")
        if isinstance(body, str):
            body = json.loads(body)

        email = (body.get("email") or "").strip().lower()
        password = body.get("password") or ""
        expected_role = (body.get("role") or "").strip().lower()

        if not email:
            return construct_response(
                HTTP_BAD_REQUEST,
                {"message": "Email is required."}
            )

        if not password:
            return construct_response(
                HTTP_BAD_REQUEST,
                {"message": "Password is required."}
            )

        if expected_role not in ["customer", "artisan", "courier", "admin"]:
            return construct_response(
                HTTP_BAD_REQUEST,
                {"message": "A valid role is required."}
            )

        response = cognito_client.initiate_auth(
            ClientId=COGNITO_CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": email,
                "PASSWORD": password
            }
        )

        logger.info("User %s authenticated successfully.", email)

        if "ChallengeName" in response:
            return construct_response(
                HTTP_OK,
                {
                    "message": "Additional authentication step required.",
                    "challenge_name": response["ChallengeName"],
                    "session": response.get("Session")
                }
            )

        cognito_sub = get_cognito_sub(email)

        if not cognito_sub:
            return construct_response(
                HTTP_INTERNAL_ERROR,
                {"message": "Unable to retrieve user information."}
            )

        user_result = db.get_user_by_cognito_sub(cognito_sub)

        if user_result["statusCode"] != HTTP_OK:
            return construct_response(
                HTTP_NOT_FOUND,
                {"message": "User record not found."}
            )

        user = user_result["body"]

        if user["role"].lower() != expected_role:
            logger.warning(
                "Access denied for %s. Expected role=%s, actual role=%s",
                email,
                expected_role,
                user["role"]
            )

            return construct_response(
                HTTP_FORBIDDEN,
                {
                    "message": "Access denied.",
                    "expected_role": expected_role,
                    "actual_role": user["role"]
                }
            )

        if not user["is_active"]:
            return construct_response(
                HTTP_FORBIDDEN,
                {"message": "Your account has been deactivated."}
            )

        authentication = response["AuthenticationResult"]

        return construct_response(
            HTTP_OK,
            {
                "message": "Login successful.",
                "user": {
                    "user_id": user["user_id"],
                    "email": user["email"],
                    "role": user["role"],
                    "cognito_sub": user["cognito_sub"]
                },
                "access_token": authentication["AccessToken"],
                "id_token": authentication["IdToken"],
                "refresh_token": authentication.get("RefreshToken"),
                "expires_in": authentication["ExpiresIn"],
                "token_type": authentication["TokenType"]
            }
        )

    except json.JSONDecodeError:
        return construct_response(
            HTTP_BAD_REQUEST,
            {"message": "Invalid JSON body."}
        )

    except cognito_client.exceptions.NotAuthorizedException:
        return construct_response(
            401,
            {"message": "Invalid email or password."}
        )

    except cognito_client.exceptions.UserNotFoundException:
        return construct_response(
            HTTP_NOT_FOUND,
            {"message": "User not found."}
        )

    except cognito_client.exceptions.UserNotConfirmedException:
        return construct_response(
            HTTP_FORBIDDEN,
            {"message": "Account has not been confirmed."}
        )

    except cognito_client.exceptions.PasswordResetRequiredException:
        return construct_response(
            HTTP_FORBIDDEN,
            {"message": "Password reset is required."}
        )

    except Exception as e:
        logger.exception("Login failed for %s", email if "email" in locals() else "unknown")

        return construct_response(
            HTTP_INTERNAL_ERROR,
            {
                "message": "Internal server error.",
                "error": str(e)
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

        # 7. Insert Admin profile into DB (tbl_admins)
        # - cognito_sub stored here directly as per tbl_admins schema
        # - department e.g. "Operations", "Finance", "Technical"
        # - designation e.g. "Super Admin", "Support Agent", "Manager"
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

    try:

        claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
        cognito_sub = claims["sub"]

        body = event.get("body")

        if isinstance(body, str):
            body = json.loads(body)

        required_fields = [
            "jobRequestId",
            "artisanId",
            "bookingDate",
            "serviceAddress",
            "agreedAmount"
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
                SELECT
                    job_request_id,
                    customer_id,
                    artisan_id,
                    status
                FROM tbl_job_requests
                WHERE job_request_id = %s
                LIMIT 1
                """,
                (body["jobRequestId"],)
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

            if job_request["customer_id"] != customer_id:
                return {
                    "statusCode": 403,
                    "body": json.dumps({
                        "success": False,
                        "message": "You are not authorized to book this job request."
                    })
                }

            if job_request["status"] != "accepted":
                return {
                    "statusCode": 400,
                    "body": json.dumps({
                        "success": False,
                        "message": "This job request has not been accepted by an artisan."
                    })
                }

            if job_request["artisan_id"] != body["artisanId"]:
                return {
                    "statusCode": 400,
                    "body": json.dumps({
                        "success": False,
                        "message": "The selected artisan did not accept this job request."
                    })
                }

            cursor.execute(
                """
                SELECT booking_id
                FROM tbl_bookings
                WHERE job_request_id = %s
                LIMIT 1
                """,
                (body["jobRequestId"],)
            )

            existing_booking = cursor.fetchone()

            if existing_booking:
                return {
                    "statusCode": 409,
                    "body": json.dumps({
                        "success": False,
                        "message": "A booking already exists for this job request."
                    })
                }

            cursor.execute(
                """
                INSERT INTO tbl_bookings
                (
                    job_request_id,
                    customer_id,
                    artisan_id,
                    booking_date,
                    service_address,
                    agreed_amount,
                    booking_status,
                    customer_notes,
                    artisan_notes
                )
                VALUES
                (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    body["jobRequestId"],
                    customer_id,
                    body["artisanId"],
                    body["bookingDate"],
                    body["serviceAddress"],
                    body["agreedAmount"],
                    "scheduled",
                    body.get("customerNotes"),
                    body.get("artisanNotes")
                )
            )

            booking_id = cursor.lastrowid

        connection.commit()

        return {
            "statusCode": 201,
            "body": json.dumps({
                "success": True,
                "bookingId": booking_id,
                "customerId": customer_id,
                "bookingStatus": "scheduled",
                "message": "Booking created successfully."
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