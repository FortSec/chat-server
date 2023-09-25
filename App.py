from typing import Dict
from flask import Flask, abort, url_for, request
from flask_httpauth import HTTPTokenAuth
from flask_socketio import *
import sys
import re
import hashlib
import uuid

from User import User, all_roles
from DataHelpers import ConsoleLog, ConstructToken, DatabaseConnection, LogClientChecksPassed, LogClientException, LogRecievedChecking, LogRecievedReplying, LogSocketRecieved, LogSocketUnauth, Print, LogRecievedReplyingAuth, GetKeyByValue
from Response import ConstructError, ConstructSuccess
from config import *

app = Flask(__name__)
sockio = SocketIO(app, logger=False, engineio_logger=False, ssl_check_certificates=False)
auth = HTTPTokenAuth(scheme='Bearer')
db_con = DatabaseConnection()
all_rooms = {}

# Load rooms
all_rooms["general"] = {
    "name": "Hlavné"
}
rooms_memebrs = {
    "general": []
}
for room in rooms:
    new_room_uuid = uuid.uuid4()
    all_rooms[str(new_room_uuid)] = {
        "name": room
    }
    rooms_memebrs[str(new_room_uuid)] = []

cached_users = {}
connected_users = {}

########################
# Authentication logic #
########################


@auth.verify_token
def verify_token(token):
    tokens = db_con.GetAllTokens()
    ConsoleLog(f"Verifying token {token}")
    if token in tokens:
        user_uuid = tokens[token]
        if user_uuid not in cached_users:
            user_name = db_con.GetUserInfo(user_uuid, 'name')
            user_mail = db_con.GetUserInfo(user_uuid, 'mail')
            user_roles = db_con.GetUserInfo(user_uuid, 'roles')
            user_roles = list(map(int, user_roles.split(',')))
            cached_users[user_uuid] = User(
                user_name, user_mail, user_uuid, user_roles)
        ConsoleLog(f"User UUID {user_uuid} is authorized")
        return user_uuid


@auth.get_user_roles
def get_user_roles(user_uuid):
    try:
        return cached_users[user_uuid].GetRoles()
    except:
        return [all_roles[0]]


@auth.error_handler
def unauthorized_auth():
    ConsoleLog('User is unauthorized')
    abort(401)

###############
# Application #
###############


@app.route('/path/<toWhat>', methods=['GET'])
def path(toWhat):
    LogRecievedReplying(f"/path/{toWhat}", request.remote_addr)
    parameters = {}
    for item in request.args:
        parameters[item] = request.args[item]
    return ConstructSuccess({
        'path': f"{server_host_url}{url_for(toWhat, **parameters)}"
    })


@app.route('/docs', methods=['GET'])
@auth.login_required(role='dev')
def docs():
    LogRecievedReplyingAuth(f"/docs", request.remote_addr)
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
                        'user_name': 'User\'s display name. It don\'t have to be unique [string]',
                        'user_password': 'User\'s password in SHA1 [string]'
                    },
                    'response': ['success', 'error'],
                    'methods': ['POST']
                },
                {
                    'url': url_for('status'),
                    'name': 'Server status',
                    'slug': 'status',
                    'desc': 'Tells the client the status of the server.',
                    'auth_required': False,
                    'parameters': None,
                    'response': ['success'],
                    'methods': ['GET']
                },
                {
                    'url': url_for('path'),
                    'name': 'Path getter',
                    'slug': 'path',
                    'desc': 'Tells the client the path to the service.',
                    'auth_required': False,
                    'parameters': None,
                    'response': ['success'],
                    'methods': ['GET']
                }
            ]
        }
    }


@app.route('/status')
def status():
    LogRecievedReplying('/status', request.remote_addr)
    return ConstructSuccess({
        'status': 'open',
        'accepts_clients': True,
        'connected_clients': len(connected_users),
        'accepts_guests': allow_guests,
        'registration_allowed': user_registration_allowed
    })

#########
# USERS #
#########

@app.route('/user', methods=['GET'])
@auth.login_required(role='normal')
def user_get():
    LogRecievedReplyingAuth('/user', request.remote_addr)
    user_uuid = auth.current_user()
    return ConstructSuccess({
        'uuid': user_uuid,
        'name': db_con.GetUserInfo(user_uuid, 'name')
    })

@app.route('/about_user/<uuid>', methods=['GET'])
@auth.login_required(role='normal')
def user_get_about(uuid):
    LogRecievedReplyingAuth('/user/about_user', request.remote_addr)
    requesting_user_uuid = auth.current_user()
    ConsoleLog(f"User {db_con.GetUserInfo(requesting_user_uuid, 'name')} is requesting an info about user {uuid}")
    return ConstructSuccess({
        'uuid': uuid,
        'name': db_con.GetUserInfo(uuid, 'name'),
        'roles': db_con.GetUserInfo(uuid, 'roles')
    })


@app.route('/user/<email>', methods=['POST'])
def user(email):
    LogRecievedChecking(f'/user/{email}', request.remote_addr)
    user_mail = email
    user_name = request.args.get('user_name')
    user_password = request.args.get('user_password')
    user_roles = request.args.get('user_roles')
    # Checks
    mail_regex = re.compile('''(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])''')
    user_name_regex = re.compile(
        '''^[a-zA-Z][a-zA-Z0-9\s_\-&]{1,36}[a-zA-Z0-9]$''')
    if not user_mail or not user_name:
        LogClientException(f'/user/{email}', request.remote_addr, 'missing data')
        return ConstructError('missing data')
    if not mail_regex.match(user_mail):
        LogClientException(f'/user/{email}', request.remote_addr, 'email not valid')
        return ConstructError('email not valid')
    if not user_name_regex.match(user_name):
        LogClientException(f'/user/{email}', request.remote_addr,
                           'display name not valid')
        return ConstructError('display name not valid')
    if db_con.EmailExists(user_mail):
        LogClientException(f'/user/{email}', request.remote_addr, 'email exists')
        return ConstructError('email exists')
    # Checks passed, register
    LogClientChecksPassed(f'/user/{email}', request.remote_addr)
    registered_uuid = db_con.InsertNewUser(
        user_mail, user_name, user_password, user_roles)
    return ConstructSuccess({
        'uuid': registered_uuid
    })


#########
# OTHER #
#########

@app.route('/fetch_rooms', methods=['GET'])
@auth.login_required(role='normal')
def fetch_rooms():
    LogRecievedReplyingAuth('/fetch_rooms', request.remote_addr)
    res = []
    for room_uuid in all_rooms.keys():
        res.append({
            "uuid": room_uuid,
            "name": all_rooms[room_uuid]["name"]
        })
    return ConstructSuccess({
        'rooms': res
    })


##############################
# SOCKET CONNECTION HANDLERS #
##############################

@sockio.on('join')
def socket_handle_join(data):
    LogSocketRecieved('JOIN', request.sid)
    uuid = verify_token(data["Token"])
    if not uuid:
        LogSocketUnauth('JOIN', request.sid)
        Emit('autherr')
        return
    if uuid in connected_users.values():
        ConsoleLog(f"User with SID {request.sid} is trying to connect with an account that is already connected")
        Emit('conerr')
        return
    ConsoleLog(f"Registered and joined user with UUID {uuid} (associated with SID {request.sid} from now)")
    connected_users[request.sid] = uuid
    data = {
        'user_name': uuid,
        'public_key': data['PublicKey']
    }
    join_room("general") # automatically connect to general on join
    rooms_memebrs["general"].append(request.sid)
    Emit('joined', data, broadcast=True)
    
@sockio.on('room_roam')
def socket_handle_room_roam(data):
    LogSocketRecieved('ROOM_ROAM', request.sid)
    uuid = verify_token(data["Token"])
    if not uuid:
        LogSocketUnauth('ROOM_ROAM', request.sid)
        Emit('autherr')
        return
    if not uuid in connected_users.values():
        ConsoleLog(f"User with SID {request.sid} is trying to roam the rooms but is not connected")
        Emit('conerr')
        return
    oldRoomUuid = data["OldRoom"]
    newRoomUuid = data["NewRoom"]
    ConsoleLog(f"User UUID {uuid} is roaming from {all_rooms[oldRoomUuid]['name'].encode('utf-8')} to {all_rooms[newRoomUuid]['name'].encode('utf-8')}")
    if request.sid in rooms_memebrs[oldRoomUuid]: rooms_memebrs[oldRoomUuid].remove(request.sid)
    if request.sid not in rooms_memebrs[newRoomUuid]: rooms_memebrs[newRoomUuid].append(request.sid)
    leave_room(oldRoomUuid)
    join_room(newRoomUuid)
    data = {
        'user': uuid
    }
    for u_sid in rooms_memebrs[oldRoomUuid]: Emit('roamed_out', data, to=u_sid)
    for u_sid in rooms_memebrs[newRoomUuid]: Emit('roamed_in', data, to=u_sid)
    
@sockio.on('certpoll')
def socket_handle_cert_poll(data):
    LogSocketRecieved('CERTPOLL', request.sid)
    uuid = verify_token(data["Token"])
    if not uuid:
        LogSocketUnauth('CERTPOLL', request.sid)
        Emit('autherr')
        return
    if not uuid in connected_users.values():
        ConsoleLog(f"User with SID {request.sid} is trying to send it's certificate but is not connected")
        Emit('conerr')
        return
    toUser = data["ToUser"]
    pubKey = data["PublicKey"]
    # ConsoleLog(f"User UUID {uuid} is roaming from {all_rooms[oldRoomUuid]['name'].encode('utf-8')} to {all_rooms[newRoomUuid]['name'].encode('utf-8')}")
    data = {
        'user': uuid,
        'pubKey': pubKey
    }
    Emit('writecert', data, to=GetKeyByValue(connected_users, toUser))


@sockio.on('mess')
def socket_handle_mess(data):
    LogSocketRecieved('MESS', request.sid)
    uuid = verify_token(data["Token"])
    message = str(data["Message"])
    fromRoom = str(data["FromRoom"])
    toUser = str(data["ToUser"])
    if not uuid:
        LogSocketUnauth('MESS', request.sid)
        Emit('autherr')
        return
    if not uuid in connected_users.values():
        ConsoleLog(f"User with SID {request.sid} is trying to send message but is not connected")
        Emit('conerr')
        return
    user_name = db_con.GetUserInfo(uuid, 'name')
    data = {
        'content': message,
        'sender': uuid
    }
    touserSid = GetKeyByValue(connected_users, toUser)
    if touserSid in rooms_memebrs[fromRoom]: Emit('newmess', data, to=touserSid)


@sockio.on('connect')
def socket_on_connect(auth):
    ConsoleLog(f"User with SID {request.sid} has registered, waiting for JOIN request...")

@sockio.on('disconnect')
def socket_on_disconnect():
    ConsoleLog(f"User with SID {request.sid} has dropped connection, handling")
    for k in rooms_memebrs.keys():
        if request.sid in rooms_memebrs[k]: rooms_memebrs[k].remove(request.sid)
    try:
        data = {
            'user_name': connected_users[request.sid]
        }
        del connected_users[request.sid]
        Emit('leaved', data, broadcast=True)
    except:
        ConsoleLog('Fatal hit on disconnect handler, avoiding crash')
        return


@sockio.on_error_default
def socket_default_err_handler(e):
    ConsoleLog(f'error {e}')

###########
# LOGGING #
###########

@sockio.on('message')
def socket_log_message(data: str):
    data = f" (data: {data})" if len(data) > 0 else ''
    ConsoleLog(f"Recieved unknown socket {request.event['message'].upper()}{data} from {request.sid}")

@sockio.on('json')
def socket_log_json(data: Dict):
    data = f" (data: {str(data)})" if data != {} else ''
    ConsoleLog(f"Recieved unknown socket {request.event['message'].upper()}{data} from {request.sid}")

def Emit(message: str, *args, **kwargs):
    try:
        data = f" (data: {str(args[0]).encode('utf-8')})"
    except IndexError:
        data = ''
    try:
        broadcast = kwargs['broadcast']
    except KeyError:
        broadcast = False
    ConsoleLog(f"Emitting {message.upper()}{data} {'back to sender' if not broadcast else 'to all'}")
    emit(message, *args, **kwargs)

############
# FOR DEVS #
############


@app.route('/dev/insertTestSubject', methods=['GET'])
#@auth.login_required(role='dev')
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
    LogClientException('N/A address', request.remote_addr,
                       'method not allowed')
    return {
        'response': 'error',
        'data': {
            'response_info': 'method not allowed'
        }
    }


@app.errorhandler(404)
def not_found(error):
    LogClientException('N/A address', request.remote_addr, 'not found')
    return {
        'response': 'error',
        'data': {
            'response_info': 'not found'
        }
    }


@app.errorhandler(403)
def unauthorized(error):
    LogClientException('N/A address', request.remote_addr,
                       'unauthorized by server')
    return {
        'response': 'error',
        'data': {
            'response_info': 'unauthorized by server'
        }
    }


@app.errorhandler(401)
def unauthorized(error):
    LogClientException('N/A address', request.remote_addr,
                       'unauthorized by token')
    return {
        'response': 'error',
        'data': {
            'response_info': 'unauthorized by token'
        }
    }


@app.errorhandler(Exception)
def other_error(error):
    LogClientException('N/A address', request.remote_addr, str(error))
    return {
        'response': 'error',
        'data': {
            'response_info': str(error)
        }
    }

if __name__ == '__main__':
    ConsoleLog('Server started successfully')
    try:
        
        sockio.run(app, host='0.0.0.0', debug=server_debug_mode, certfile='certs/cert.pem', keyfile='certs/key.pem')
        # sockio.run(app, host='0.0.0.0', debug=server_debug_mode)
        
    except KeyboardInterrupt:
        ConsoleLog('Server shutting down due to keyboard interrupt')

