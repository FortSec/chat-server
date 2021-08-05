from flask import Flask, abort
from flask_httpauth import HTTPTokenAuth
import sys

from User import User, all_roles
from DataHelpers import DatabaseConnection

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
    # try:
    print(str(cached_users[user_uuid].GetRolesID()), file=sys.stdout)
    return cached_users[user_uuid].GetRoles()
    # except:
    #    return [all_roles[0]]


@auth.error_handler
def unauthorized_auth():
    abort(401)

###############
# Application #
###############


@app.route('/', methods=['GET'])
def index():
    return {
        'response': 'usage',
        'data': {
            'all_routes': [
                {
                    'name': 'Usage of the RESTful API',
                    'slug': 'index',
                    'desc': 'Basic usage of this API, containing all needed information.',
                    'auth_required': False,
                    'parameters': None,
                    'response': ['usage']
                },
                {
                    'name': 'DEV Only: Insert testing subject',
                    'slug': 'dev_insertTestSubject',
                    'desc': 'Inserts testing subject with predefined info for testing.',
                    'auth_required': ['dev'],
                    'parameters': None,
                    'response': ['success']
                },
                {
                    'name': 'DEV Only: Test permissions',
                    'slug': 'dev_testPermissions',
                    'desc': 'Does not display error only if permissions are right.',
                    'auth_required': ['dev'],
                    'parameters': None,
                    'response': ['success']
                }
            ]
        }
    }


@app.route('/dev/insertTestSubject', methods=['GET'])
@auth.login_required(role='dev')
def dev_insertTestSubject():
    testing_subj_uuid = db_con.InsertTestSubject()
    return {
        'response': 'success',
        'data': {
            'new_uuid': testing_subj_uuid
        }
    }


@app.route('/dev/testPermissions', methods=['GET'])
@auth.login_required(role='dev')
def dev_testPermissions():
    return {
        'response': 'success',
        'data': {}
    }

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


# @app.errorhandler(Exception)
# def other_error(error):
#     return {
#         'response': 'error',
#         'data': {
#             'response_info': str(error)
#         }
#     }


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
