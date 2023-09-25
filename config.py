# Basic server config

server_host_url = 'https://jachtarska61.ddns.net:5000/'
allow_guests = False
user_registration_allowed = False

server_debug_mode = False


### Rooms (general is always created)

rooms = [
    'Tajné veci',
    'Tuto sa nepozerať'
]

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
