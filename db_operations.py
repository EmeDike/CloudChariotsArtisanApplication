import json
import logging

import pymysql
from pymysql.cursors import DictCursor
from dotenv import load_dotenv
from datetime import datetime
import boto3

import os

load_dotenv()

class DBOperations:
    def __init__(self, database_config):
        self.connection = pymysql.connect(**database_config)
        self.connection.autocommit = False  # Disable autocommit to enable transactions

    def begin_transaction(self):
        self.connection.commit()
        self.connection.autocommit = False

    def commit_transaction(self):
        self.connection.commit()

    def rollback_transaction(self):
        self.connection.rollback()

    def execute_query(self, query, params=None, fetch_one=False):
        try:
            cursor = self.connection.cursor(
                pymysql.cursors.DictCursor
            )

            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            if fetch_one:
                result = cursor.fetchone()
            else:
                result = cursor.fetchall()

            cursor.close()

            return result

        except pymysql.MySQLError as e:
            self.connection.rollback()
            raise Exception(f"MySQL Error: {str(e)}")

    def close_connection(self):
        if self.connection:
            self.connection.close()

    # ----------------------------------------------------------------
    # tbl_users
    # ----------------------------------------------------------------
    def insert_user(self, data):
        try:
            query = """
                INSERT INTO tbl_users (
                    cognito_sub, first_name, last_name,
                    email, phone_number, role,
                    is_active, created_at, updated_at
                ) VALUES (
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s
                )
            """
            params = (
                data["cognito_sub"],
                data["first_name"],
                data["last_name"],
                data["email"],
                data["phone_number"],
                data["role"],
                data.get("is_active", 1),
                data.get("created_at", datetime.now()),
                data.get("updated_at", datetime.now())
            )
            cursor = self.connection.cursor(pymysql.cursors.DictCursor)
            cursor.execute(query, params)
            self.connection.commit()
            user_id = cursor.lastrowid
            cursor.close()
            return {
                "statusCode": 200,
                "body": {"user_id": user_id}
            }
        except pymysql.MySQLError as e:
            self.connection.rollback()
            return {
                "statusCode": 500,
                "body": {"error": f"Failed to insert user: {str(e)}"}
            }

    def get_user_by_cognito_sub(self, cognito_sub):
        try:
            query = """
                SELECT user_id, cognito_sub, first_name, last_name,
                       email, phone_number, role, is_active,
                       created_at, updated_at
                FROM tbl_users
                WHERE cognito_sub = %s
                LIMIT 1
            """
            cursor = self.connection.cursor(pymysql.cursors.DictCursor)
            cursor.execute(query, (cognito_sub,))
            result = cursor.fetchone()
            cursor.close()
            if not result:
                return {
                    "statusCode": 404,
                    "body": {"error": "User not found."}
                }
            return {
                "statusCode": 200,
                "body": result
            }
        except pymysql.MySQLError as e:
            self.connection.rollback()
            return {
                "statusCode": 500,
                "body": {"error": f"Failed to fetch user: {str(e)}"}
            }

    # ----------------------------------------------------------------
    # tbl_address
    # ----------------------------------------------------------------
    def insert_address(self, data):
        try:
            query = """
                INSERT INTO tbl_addresses (
                    user_id, label, address,
                    city, state, latitude, longitude
                ) VALUES (
                    %s, %s, %s,
                    %s, %s, %s, %s
                )
            """
            params = (
                data["user_id"],
                data["label"],
                data["address"],
                data["city"],
                data["state"],
                data["latitude"],
                data["longitude"]
            )
            cursor = self.connection.cursor(pymysql.cursors.DictCursor)
            cursor.execute(query, params)
            self.connection.commit()
            address_id = cursor.lastrowid
            cursor.close()
            return {
                "statusCode": 200,
                "body": {"address_id": address_id}
            }
        except pymysql.MySQLError as e:
            self.connection.rollback()
            return {
                "statusCode": 500,
                "body": {"error": f"Failed to insert address: {str(e)}"}
            }

    # ----------------------------------------------------------------
    # tbl_artisan
    # ----------------------------------------------------------------
    def insert_artisan(self, data):
        try:
            query = """
                INSERT INTO tbl_artisans (
                    user_id, business_name, years_of_experience,
                    bio, average_rating, total_reviews,
                    verification_status, is_available,
                    created_at, updated_at
                ) VALUES (
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s,
                    %s, %s
                )
            """
            params = (
                data["user_id"],
                data["business_name"],
                data["years_of_experience"],
                data["bio"],
                data.get("average_rating", 0.00),
                data.get("total_reviews", 0),
                data.get("verification_status", "pending"),
                data.get("is_available", 1),
                data.get("created_at", datetime.now()),
                data.get("updated_at", datetime.now())
            )
            cursor = self.connection.cursor(pymysql.cursors.DictCursor)
            cursor.execute(query, params)
            self.connection.commit()
            artisan_id = cursor.lastrowid
            cursor.close()
            return {
                "statusCode": 200,
                "body": {"artisan_id": artisan_id}
            }
        except pymysql.MySQLError as e:
            self.connection.rollback()
            return {
                "statusCode": 500,
                "body": {"error": f"Failed to insert artisan: {str(e)}"}
            }

    # ----------------------------------------------------------------
    # tbl_customers
    # ----------------------------------------------------------------
    def insert_customer(self, data):
        try:
            query = """
                INSERT INTO tbl_customers (
                    user_id, cognito_sub, player_id,
                    profile_image, status,
                    created_at, updated_at
                ) VALUES (
                    %s, %s, %s,
                    %s, %s,
                    %s, %s
                )
            """
            params = (
                data["user_id"],
                data["cognito_sub"],
                data.get("player_id"),
                data.get("profile_image"),
                data.get("status", "active"),
                data.get("created_at", datetime.now()),
                data.get("updated_at", datetime.now())
            )
            cursor = self.connection.cursor(pymysql.cursors.DictCursor)
            cursor.execute(query, params)
            self.connection.commit()
            customer_id = cursor.lastrowid
            cursor.close()
            return {
                "statusCode": 200,
                "body": {"customer_id": customer_id}
            }
        except pymysql.MySQLError as e:
            self.connection.rollback()
            return {
                "statusCode": 500,
                "body": {"error": f"Failed to insert customer: {str(e)}"}
            }

    # ----------------------------------------------------------------
    # tbl_admins
    # ----------------------------------------------------------------
    def insert_admin(self, data):
        try:
            query = """
                INSERT INTO tbl_admins (
                    user_id, cognito_sub,
                    department, designation,
                    created_at, updated_at
                ) VALUES (
                    %s, %s,
                    %s, %s,
                    %s, %s
                )
            """
            params = (
                data["user_id"],
                data["cognito_sub"],
                data["department"],
                data["designation"],
                data.get("created_at", datetime.now()),
                data.get("updated_at", datetime.now())
            )
            cursor = self.connection.cursor(pymysql.cursors.DictCursor)
            cursor.execute(query, params)
            self.connection.commit()
            admin_id = cursor.lastrowid
            cursor.close()
            return {
                "statusCode": 200,
                "body": {"admin_id": admin_id}
            }
        except pymysql.MySQLError as e:
            self.connection.rollback()
            return {
                "statusCode": 500,
                "body": {"error": f"Failed to insert admin: {str(e)}"}
            }

    # ----------------------------------------------------------------
    # tbl_wallets
    # ----------------------------------------------------------------
    def insert_wallet(self, data):
        try:
            query = """
                INSERT INTO tbl_wallets (
                    owner_id, owner_type, currency,
                    balance, status
                ) VALUES (
                    %s, %s, %s,
                    %s, %s
                )
            """
            params = (
                data["owner_id"],
                data["owner_type"],
                data.get("currency", "NGN"),
                data.get("balance", 0.00),
                data.get("status", "active")
            )
            cursor = self.connection.cursor(pymysql.cursors.DictCursor)
            cursor.execute(query, params)
            self.connection.commit()
            wallet_id = cursor.lastrowid
            cursor.close()
            return {
                "statusCode": 200,
                "body": {"wallet_id": wallet_id}
            }
        except pymysql.MySQLError as e:
            self.connection.rollback()
            return {
                "statusCode": 500,
                "body": {"error": f"Failed to insert wallet: {str(e)}"}
            }


# ----------------------------------------------------------------
# Bootstrap DB connection from SSM Parameter Store
# ----------------------------------------------------------------
ssm_client = boto3.client('ssm', region_name='eu-west-2')

param_names = [
    'DB_HOST',
    'DB_NAME',
    'DB_USER',
    'DB_PASSWORD',
    'DB_PORT'
]

response = ssm_client.get_parameters(
    Names=param_names,
    WithDecryption=True
)

parameter_dict = {param['Name']: param['Value'] for param in response['Parameters']}

database_config = {
    "host":     parameter_dict['DB_HOST'],
    "database": parameter_dict['DB_NAME'],
    "user":     parameter_dict['DB_USER'],
    "password": parameter_dict['DB_PASSWORD'],
    "port":     int(parameter_dict['DB_PORT'])
}

db = DBOperations(database_config)
# add this line
connection = db.connection
