# Basic server config

server_host_url = 'http://192.168.100.79:5000'
allow_guests = False
user_registration_allowed = False

server_debug_mode = False


#### Roles and permissions

all_roles = [
    'banned',
    'erroneous',
    'normal',
    'mod',
    'admin',
    'dev'
]

team_thresh_id = 3
default_role_id = 2
erroneous_role_id = 1
