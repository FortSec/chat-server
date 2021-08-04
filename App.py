# AWS RDS SQL user: admin
# AWS RDS SQL pwd: 2z36l9ujLOnqIoExDhgn

from flask import Flask, abort
from flask_httpauth import HTTPTokenAuth

app = Flask(__name__)
auth = HTTPTokenAuth(scheme='Bearer')

tokens = {
    'abc123': 'Anton',
    'def098': 'Marek'
}


@auth.verify_token
def verify_token(token):
    if token in tokens:
        return tokens[token]


@auth.get_user_roles
def get_user_roles(user):
    return user.get_roles()


@auth.error_handler
def unauthorized_auth():
    abort(401)

###############
# Application #
###############


@app.route('/')
def index():
    return {
        'response': 'usage',
        'data': {
            'all_routes': [
                {
                    'name': 'Usage of the RESTful API',
                    'slug': 'usage',
                    'desc': 'Basic usage of this API, containing all needed information.',
                    'auth_required': False,
                    'parameters': None,
                    'response': ['usage']
                }
            ]
        }
    }

##################
# Error handlers #
##################


@app.errorhandler(404)
def not_found(error):
    return {
        'response': 'error',
        'response_info': 'not found'
    }


@app.errorhandler(403)
def unauthorized(error):
    return {
        'response': 'error',
        'response_info': 'unauthorized by server'
    }


@app.errorhandler(401)
def unauthorized(error):
    return {
        'response': 'error',
        'response_info': 'unauthorized by credentials'
    }


@app.errorhandler(Exception)
def other_error(error):
    return {
        'response': 'error',
        'response_info': str(error)
    }


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
