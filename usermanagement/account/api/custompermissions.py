from rest_framework.response import Response
from account.models import Account
from rest_framework.permissions import BasePermission


class adminpermission(BasePermission):
    def has_permission(self, request, view):
        user = request.user

        user_roles = Account.objects.get(email=user).roles
        if user_roles == 'admin':
            return True
        else:
            return False


class userpermissions(BasePermission):
    def has_permission(self, request, view):
        user = request.user

        user_roles = Account.objects.get(email=user).roles
        if user_roles == 'user':
            return True
        else:
            return False


class Allpermissions(BasePermission):
    def has_permission(self, request, view):
        user = request.user

        user_roles = Account.objects.get(email=user).roles
        if user_roles == 'user' or user_roles == 'admin':
            return True
        else:
            return False
