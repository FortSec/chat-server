import sqlite3 as sl
import uuid

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

    def GetUserInfo(self, user_uuid, what):
        try:
            data = self.GetData(
                'Users', f'user_uuid=\'{user_uuid}\'', f'user_{what}')[0][0]
        except:
            data = 'FATAL_WHILE_READING'
        return data

    def InsertTestSubject(self):
        con = sl.connect(f'{self.db_name}.db')
        with con:
            new_uuid = uuid.uuid4()
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
                    'f9d847d226e5eb470966e661c9636216da4d77aa870ec74bee047b3e83625f66'
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
                    '51cf2e88b729ce0022d412af9de1fc206566ec65e558365bf4212fd8ad92a102'
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
