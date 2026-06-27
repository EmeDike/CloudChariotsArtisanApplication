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
    "host": parameter_dict['DB_HOST'],
    "database": parameter_dict['DB_NAME'],
    "user": parameter_dict['DB_USER'],
    "password": parameter_dict['DB_PASSWORD'],
    "port": int(parameter_dict['DB_PORT'])
}

db = DBOperations(database_config)