import sqlite3 as sl
import uuid
import hashlib
import time
import math
import sys
import datetime

from config import *


class DatabaseConnection:
    def __init__(self, db_name='master'):
        self.db_name = db_name
        con = sl.connect(f'{self.db_name}.db')
        with con:
            cur = con.cursor()
            cur.executescript('''
                CREATE TABLE IF NOT EXISTS Users(
                    user_uuid VARCHAR(64) NOT NULL PRIMARY KEY,
                    user_name VARCHAR(128),
                    user_mail VARCHAR(128),
                    user_roles TEXT,
                    user_reg_time INTEGER
                );
                CREATE TABLE IF NOT EXISTS Tokens(
                    user_uuid VARCHAR(64),
                    user_token VARCHAR(64)
                );
            ''')
            con.commit()

    def GetAllTokens(self):
        con = sl.connect(f'{self.db_name}.db')
        with con:
            data = con.execute('''
                SELECT * FROM Tokens;
            ''').fetchall()
            con.commit()
            return_data = {}
            for row in data:
                return_data[row[1]] = row[0]
            return return_data

    def EmailExists(self, mail):
        con = sl.connect(f'{self.db_name}.db')
        with con:
            data = con.execute(f'''
                SELECT * FROM Users WHERE user_mail='{mail}';
            ''').fetchall()
            con.commit()
            return len(data) > 0

    def InsertNewUser(self, mail, name, password, roles):
        user_token = ConstructToken(mail, password)
        user_uuid = uuid.uuid4()
        user_name = name
        user_roles = roles
        user_mail = mail
        user_reg_time = int(time.time())
        con = sl.connect(f'{self.db_name}.db')
        with con:
            cur = con.cursor()
            cur.executescript(f'''
                INSERT INTO Users (user_uuid, user_name, user_mail, user_roles, user_reg_time) VALUES (
                    '{user_uuid}',
                    '{user_name}',
                    '{user_mail}',
                    '{user_roles}',
                    {user_reg_time}
                );
                INSERT INTO Tokens (user_uuid, user_token) VALUES (
                    '{user_uuid}',
                    '{user_token}'
                );
            ''')
            return user_token

    def GetUserInfo(self, user_uuid, what):
        try:
            data = self.GetData(
                'Users', f'user_uuid=\'{user_uuid}\'', f'user_{what}')[0][0]
        except:
            data = 'FATAL_WHILE_READING'
        return data

    def FetchUUID(self, token):
        try:
            data = self.GetData('Tokens', f'user_token=\'{token}\'', 'user_uuid')
        except:
            data = 'err'
        return data

    def InsertTestSubject(self):
        con = sl.connect(f'{self.db_name}.db')
        with con:
            new_uuid = uuid.uuid4()
            new_uuid1 = uuid.uuid4()
            cur = con.cursor()
            cur.executescript(f'''
                INSERT INTO Users (user_uuid, user_name, user_mail, user_roles, user_reg_time) VALUES (
                    'b62cda51-468c-4f45-a3cc-edbbdfefc35e',
                    'Testing subject',
                    'testing@esec.sk',
                    '2',
                    1628157002
                );
                INSERT INTO Tokens (user_uuid, user_token) VALUES (
                    'b62cda51-468c-4f45-a3cc-edbbdfefc35e',
                    '431158c9b4e61ac02aa9d987e24241bdac332e094f00b34ea1f9b19a313fdb15'
                );
                INSERT INTO Users (user_uuid, user_name, user_mail, user_roles, user_reg_time) VALUES (
                    '{new_uuid}',
                    'Anton Pernisch',
                    'services@esec.sk',
                    '2,5',
                    1628165540
                );
                INSERT INTO Tokens (user_uuid, user_token) VALUES (
                    '{new_uuid}',
                    '985cd129f602e24037e8b7df9977e60e57bc91293c0755b815c59406fde4e6e8'
                );
                INSERT INTO Users (user_uuid, user_name, user_mail, user_roles, user_reg_time) VALUES (
                    '{new_uuid1}',
                    'Ernest Habán',
                    'ernesthaban679@gmail.com',
                    '2,5',
                    1628165540
                );
                INSERT INTO Tokens (user_uuid, user_token) VALUES (
                    '{new_uuid1}',
                    'd3afeb0ba4f8fe4d6aee4c6516a500255fa0cc19216ede767abcd58703f5cc68'
                );
            ''')
            con.commit()
            return new_uuid

    def GetData(self, table, selector_expr, sel_what='*'):
        con = sl.connect(f'{self.db_name}.db')
        with con:
            data = con.execute(f'''
                SELECT {sel_what} FROM {table} WHERE {selector_expr};
            ''').fetchall()
            con.commit()
            return data


def ConstructToken(mail, password_sha1):
    string = f"::({mail}):({password_sha1}):::-"
    string = hashlib.md5(string).hexdigest()
    string = hashlib.sha256(string).hexdigest()
    return string


def Print(str):
    print(str, file=sys.stdout)


def ConsoleLog(message):
    Print(
        f"[FortSec chat server - {datetime.datetime.now().strftime('%H:%M:%S')}] {message}")


def LogRecievedReplying(address, remote):
    ConsoleLog(f"({address}) Recieved from {remote}, replying")


def LogRecievedChecking(address, remote):
    ConsoleLog(f"({address}) Recieved from {remote}, checking")


def LogClientException(address, remote, message='Undefined'):
    ConsoleLog(f"({address}) Exception to {remote}: {message}")


def LogClientChecksPassed(address, remote):
    ConsoleLog(
        f"({address}) Checks passed for {remote}, replying with success")


def LogRecievedReplyingAuth(address, remote):
    ConsoleLog(f"({address}) Recieved and authorized from {remote}, replying")

def LogSocketRecieved(sock, sid):
    ConsoleLog(f"Socket {sock} recieved from {sid}, processing...")

def LogSocketUnauth(sock, sid):
    ConsoleLog(f"Socket {sock} request has been denied from {sid} because of bad credentials")
