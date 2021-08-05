from flask import Flask, abort, url_for, request
from flask_httpauth import HTTPTokenAuth
import sys
import re

from User import User, all_roles
from DataHelpers import DatabaseConnection
from Response import ConstructError, ConstructSuccess

app = Flask(__name__)
auth = HTTPTokenAuth(scheme='Bearer')
db_con = DatabaseConnection()

cached_users = {}

########################
# Authentication logic #
########################


@auth.verify_token
def verify_token(token):
    tokens = db_con.GetAllTokens()
    if token in tokens:
        user_uuid = tokens[token]
        if user_uuid not in cached_users:
            user_name = db_con.GetUserInfo(user_uuid, 'name')
            user_mail = db_con.GetUserInfo(user_uuid, 'mail')
            user_roles = db_con.GetUserInfo(user_uuid, 'roles')
            user_roles = list(map(int, user_roles.split(',')))
            cached_users[user_uuid] = User(
                user_name, user_mail, user_uuid, user_roles)
        return user_uuid


@auth.get_user_roles
def get_user_roles(user_uuid):
    try:
        return cached_users[user_uuid].GetRoles()
    except:
        return [all_roles[0]]


@auth.error_handler
def unauthorized_auth():
    abort(401)

###############
# Application #
###############


@app.route('/docs', methods=['GET'])
@auth.login_required(role='dev')
def docs():
    return {
        'response': 'docs',
        'data': {
            'all_routes': [
                {
                    'url': url_for('docs'),
                    'name': 'Usage of the RESTful API',
                    'slug': 'docs',
                    'desc': 'Basic usage of this API, containing all needed information.',
                    'auth_required': ['dev'],
                    'parameters': None,
                    'response': ['docs'],
                    'methods': ['GET']
                },
                {
                    'url': url_for('dev_insertTestSubject'),
                    'name': 'DEV Only: Insert testing subject',
                    'slug': 'dev_insertTestSubject',
                    'desc': 'Inserts testing subject with predefined info for testing.',
                    'auth_required': ['dev'],
                    'parameters': None,
                    'response': ['success'],
                    'methods': ['GET']
                },
                {
                    'url': url_for('dev_testPermissions'),
                    'name': 'DEV Only: Test permissions',
                    'slug': 'dev_testPermissions',
                    'desc': 'Does not display error only if permissions are right.',
                    'auth_required': ['dev'],
                    'parameters': None,
                    'response': ['success'],
                    'methods': ['GET']
                },
                {
                    'url': url_for('user'),
                    'name': 'User registration',
                    'slug': 'user',
                    'desc': 'Registeres new user.',
                    'auth_required': False,
                    'parameters': {
                        'user_mail': 'User\'s mail that will be used as his ID [string]',
                        'user_name': 'User\'s display name. It don\'t have to be unique [string]',
                        'user_password': 'User\'s password in SHA1 [string]'
                    },
                    'response': ['success', 'error'],
                    'methods': ['POST']
                }
            ]
        }
    }

#########
# USERS #
#########


@app.route('/user', methods=['POST'])
def user():
    user_mail = request.args.get('user_mail')
    user_name = request.args.get('user_name')
    user_password = request.args.get('user_password')
    user_roles = request.args.get('user_roles')
    # Checks
    mail_regex = re.compile('''(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])''')
    user_name_regex = re.compile(
        '''^[a-zA-Z][a-zA-Z0-9\s_\-&]{1,36}[a-zA-Z0-9]$''')
    if not user_mail or not user_name:
        return ConstructError('missing data')
    if not mail_regex.match(user_mail):
        return ConstructError('email not valid')
    if not user_name_regex.match(user_name):
        return ConstructError('display name not valid')
    if db_con.EmailExists(user_mail):
        return ConstructError('email exists')
    # Checks passed, register
    registered_uuid = db_con.InsertNewUser(
        user_mail, user_name, user_password, user_roles)
    return ConstructSuccess({
        'uuid': registered_uuid
    })

############
# FOR DEVS #
############


@app.route('/dev/insertTestSubject', methods=['GET'])
@auth.login_required(role='dev')
def dev_insertTestSubject():
    testing_subj_uuid = db_con.InsertTestSubject()
    return ConstructSuccess({
        'new_uuid': testing_subj_uuid
    })


@app.route('/dev/testPermissions', methods=['GET'])
@auth.login_required(role='dev')
def dev_testPermissions():
    return ConstructSuccess()

##################
# Error handlers #
##################


@app.errorhandler(405)
def not_found(error):
    return {
        'response': 'error',
        'data': {
            'response_info': 'method not allowed'
        }
    }


@app.errorhandler(404)
def not_found(error):
    return {
        'response': 'error',
        'data': {
            'response_info': 'not found'
        }
    }


@app.errorhandler(403)
def unauthorized(error):
    return {
        'response': 'error',
        'data': {
            'response_info': 'unauthorized by server'
        }
    }


@app.errorhandler(401)
def unauthorized(error):
    return {
        'response': 'error',
        'data': {
            'response_info': 'unauthorized by token'
        }
    }


@app.errorhandler(Exception)
def other_error(error):
    return {
        'response': 'error',
        'data': {
            'response_info': str(error)
        }
    }


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
