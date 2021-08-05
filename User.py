import uuid

from DataHelpers import *
from config import *


class User:
    def __init__(self, name, mail, user_uuid=None, user_roles=None):
        '''Creates new user.'''
        self.name = name
        self.mail = mail
        if not user_uuid:
            self.uuid = uuid.uuid4()
        else:
            self.uuid = user_uuid
        if not user_roles:
            self.roles = [default_role_id]
        else:
            self.roles = user_roles

    ###########
    # Setters #
    ###########

    def SetName(self, new_name):
        self.name = new_name

    def SetMail(self, new_mail):
        self.mail = new_mail

    def AddRole(self, new_role_id):
        self.roles.append(new_role_id)

    def SetRoles(self, roles_list):
        self.roles = roles_list

    def RemRole(self, rem_role_id):
        while rem_role_id in self.roles:
            self.roles.remove(rem_role_id)

    ###########
    # Getters #
    ###########

    def GetName(self):
        return self.name

    def GetMail(self):
        return self.mail

    def GetRolesID(self):
        roles = self.roles
        roles.sort()
        return roles

    def GetRoles(self):
        this_roles = self.GetRolesID()
        return_roles = []
        for index in range(len(this_roles)):
            return_roles.append(all_roles[this_roles[index]])
        return return_roles

    def GetUUID(self):
        return self.uuid
