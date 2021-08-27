import base64

from numpy.core.numeric import False_
from account.api.custompermissions import Allpermissions, adminpermission, userpermissions
import django.conf.urls
import json
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.sites.shortcuts import get_current_site
import pdb

from rest_framework.authtoken.models import Token
from account.models import Account
from account.api.serializers import AccountSerialzer, ChangePasswordSerializer, RegistrationSerializer, ResetPasswordEmailRequestSerializer, SetNewPasswordSerializer
from rest_framework import filters
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import BasicAuthentication, SessionAuthentication, TokenAuthentication
from django.contrib.auth import authenticate
from rest_framework.generics import DestroyAPIView, GenericAPIView, ListAPIView, UpdateAPIView
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from rest_framework import generics
from django.urls import reverse
from rest_framework import status
from django_filters.rest_framework import DjangoFilterBackend
from django_filters.filters import OrderingFilter
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
import numpy as np
from django.utils.encoding import DjangoUnicodeDecodeError, smart_bytes, smart_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import collections
from account.utils import Util
from django.contrib.auth.hashers import make_password


# from account.api.serializers import ResetPasswordEmailRequestSerializer, SetNewPasswordSerializer,ChangePasswordSerializer

# Register
# Url: https://<your-domain>/api/account/register

def validate_email(email):
    account = None
    try:
        account = Account.objects.get(email=email)
    except Account.DoesNotExist:
        return None
    if account != None:
        return email


@api_view(['POST', ])
@permission_classes([])
@authentication_classes([JWTAuthentication,])
def registration_view(request):
    if request.method == 'POST':
        data = {}

        args_list = list(request.data.keys())
        entities = ['first_name', 'last_name', 'email',
                    'password', 'password2']
        non_entered_fields = np.setdiff1d(entities, args_list)
        if len(non_entered_fields) > 0:
            return Response({"message": "{} is required".format(non_entered_fields[0]),
                             "status": 400})

        email = request.data.get('email', '0').lower()

        if validate_email(email) != None:
            data['message'] = 'That email is already in use.'
            data['status'] = 400
            return Response(data)
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            account = serializer.save()
            this_id = Account.objects.latest('id')
            current_site = get_current_site(request).domain
            email_body = "hi "+' \n Welcome to teamworks'

            data = {
                'email_body': email_body,
                'to_email': account.email,
                'email_subject': "welcome mail"
            }
            # Util.send_email(data)
            user = {}
            user['email'] = account.email
            profile = {}
            profile['first_name'] = account.first_name
            profile['last_name'] = account.last_name
            profile['email'] = account.email
            serializer = AccountSerialzer(account, many=False)
            return Response({"message": "User registered successfully", "status": 200, "user": serializer.data})
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
@authentication_classes(JWTAuthentication)
@permission_classes((AllowAny,IsAuthenticated))
def login(request):
    email = request.data.get("email")
    password = request.data.get("password")
    profile = {}
    if email is None or password is None:
        return Response({'error': 'Please provide both username and password'},
                        status=HTTP_400_BAD_REQUEST)
    user = authenticate(username=username, password=password)
    if not user:
        return Response({'error': 'Invalid Credentials'},
                        status=HTTP_404_NOT_FOUND)
    token, _ = Token.objects.get_or_create(user=user)
    return Response({'token': token.key},
                    status=HTTP_200_OK)   

# LOGIN
# URL: http://127.0.0.1:8000/api/account/login


class ObtainAuthTokenView(APIView):

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        try:
            email = request.data.get('email')
            password = request.data.get('password')

            if email is None:
                raise ValidationError(
                    {"message": "Email is required", "status": 400})
            if password is None:
                raise ValidationError(
                    {"message": "Password is required", "status": 400})
            user_id = Account.objects.get(
                email=email.lower()).id
            user_obj = Account.objects.get(email=email.lower())
            
            account = authenticate(email=email, password=password)
        
            if account:
                try:
                    token = Token.objects.get(user=account)
                except Token.DoesNotExist:
                    token = Token.objects.create(user=account)
                context = {}
                context['message'] = "User login successfully"
                context['status'] = 200
                context['tokentype'] = "Token"
                context['access_token'] = token.key
                profile = {}
                profile['id'] = user_id
                profile['first_name'] = user_obj.first_name
                profile['last_name'] = user_obj.last_name
                profile['email'] = email
            else:
                context = {}
                context['message'] = "invalid credentials"
                context['status'] = 400

        except RuntimeError:
            context = {}
            context['message'] = "invalid credentials"
            context['status'] = 400
        return Response({"data": context})


@ api_view(['GET', ])
@ permission_classes([])
@ authentication_classes([JWTAuthentication])
def does_account_exist_view(request):

    if request.method == 'GET':
        email = request.data.get('email', '0').lower()
        data = {}
        try:
            account = Account.objects.get(email=email)
            data['message'] = email
        except Account.DoesNotExist:
            data['message'] = "Account does not exist"
            data['status'] = 400
        return Response(data)


class ChangePasswordView(UpdateAPIView):

    serializer_class = ChangePasswordSerializer
    model = Account
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):

        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)
        entities = ['old_password', 'new_password', 'confirm_new_password']
        data = {}
        args_list = list(request.data.keys())
        non_entered_fields = np.setdiff1d(entities, args_list)
        if len(non_entered_fields) > 0:
            return Response({"message": "{} is required".format(non_entered_fields[0]),
                             "status": 400})

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({'message': "Wrong old password", 'status': 400})

            # confirm the new passwords match
            new_password = serializer.data.get("new_password")
            confirm_new_password = serializer.data.get("confirm_new_password")
            if new_password != confirm_new_password:
                return Response({"message": "New passwords must match", 'status': 400})

            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            return Response({"message": "successfully changed password", 'status': 200})

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# usercreate api


class NewUserCreate(APIView):
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated, adminpermission,)

    def post(self, request, format=None):
        data = {}
        args_list = list(request.data.keys())
        entities = ['first_name', 'last_name', 'email',]
        non_entered_fields = np.setdiff1d(entities, args_list)
        if len(non_entered_fields) > 0:
            return Response({"message": "{} is required".format(non_entered_fields[0]),
                             "status": 400})
        email = request.data.get('email', '0').lower()

        if validate_email(email) != None:
            data['message'] = 'That email is already in use.'
            data['status'] = 400
            return Response(data)
        password_before = request.data.get('password')
        password1 = make_password(password_before)
        request.data['password'] = password1
        serializer = AccountSerialzer(data=request.data)
        if serializer.is_valid():
            account = serializer.save()
            this_id = Account.objects.latest('id')

            current_site = get_current_site(request).domain
            email_body = "hi "+account.email + \
                ' \n given below your login credentials \n email:{} \n password:{}'.format(
                    account.email, password_before)

            data = {
                'email_body': email_body,
                'to_email': account.email,
                'email_subject': "Login credentials mail"
            }

            # Util.send_email(data)

            return Response({'message': 'user is created', 'status': 200,'data':serializer.data})
        return Response({"message": serializer.errors, "status": status.HTTP_400_BAD_REQUEST})


class UserListView(ListAPIView):
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated, adminpermission,)

    queryset = Account.objects.all().order_by(
        '-pk')
    serializer_class = AccountSerialzer
    filter_backends = [DjangoFilterBackend,
                       filters.SearchFilter, filters.OrderingFilter]



    search_fields = ['email', 'first_name']
    ordering_fields = ['pk']


class UserUpdate(APIView):
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated, Allpermissions,)

    def put(self, request, pk, format=None):
        try:
            if pk is not None:
                try:
                    user = Account.objects.get(id=pk)
                except Account.DoesNotExist:
                    return Response({'message': 'No User Found with this id  {}'.format(pk), 'status': status.HTTP_400_BAD_REQUEST})
            serializer = AccountSerialzer(
                user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({'message': 'user is updated successfully',
                                 'status': 200,'data':serializer.data})

            return Response({"message": serializer.errors, "status": status.HTTP_400_BAD_REQUEST})
        except RuntimeError:
            return Response({'message': 'something went wrong', 'status': 400})

    def patch(self, request, pk, format=None):
        try:
            if pk is not None:
                try:
                    user = Account.objects.get(id=pk)
                except Account.DoesNotExist:
                    return Response({'message': 'No User Found with this id  {}'.format(pk), 'status': status.HTTP_400_BAD_REQUEST})
            serializer = AccountSerialzer(
                user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({'message': 'user is updated successfully',
                                 'status': 200,'data':serializer.data})
            return Response({"message": serializer.errors, "status": status.HTTP_400_BAD_REQUEST})
        except RuntimeError:
            return Response({'message': 'something went wrong', 'status': 400})


class UserDelete(APIView):
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated, adminpermission,)

    def delete(self, request, pk, format=None):
        try:
            if pk is not None:
                try:
                    user = Account.objects.get(id=pk)
                except Account.DoesNotExist:
                    return Response({'message': 'No User Found with this id  {}'.format(pk), 'status': status.HTTP_400_BAD_REQUEST})
            user.delete()
            return Response({'message': 'user is deleted', 'status': 200})
        except RuntimeError:
            return Response({'message': 'something went wrong', 'status': 400})


# # password reset api:

class RequestPasswordResetEmail(GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data['email']
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain

            relativeLink = reverse('password_reset_confirm',
                                   kwargs={'uidb64': uidb64, 'token': token})
            absurl = 'http://'+current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your password  \n' + absurl
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
            # Util.send_email(data)

        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = Account.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)

            return Response({'success': True, 'message': 'Credentials Valid', 'uidb64': uidb64, 'token': token}, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user):
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordAPIView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


class UserInfoView(APIView):
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated, Allpermissions,)

    def get(self, request, pk=None, form=None):
        id = pk
        email = Account.objects.get(id=id).email
        if str(request.user) == email:
            if id is not None:

                try:
                    users = Account.objects.get(id=id)
                    user_info = {}
                    user_info['user_id'] = id
                    user_info['first_name'] = users.first_name
                    user_info['last_name'] = users.last_name
                    user_info['email'] = users.email
                    user_info['last_login'] = users.last_login
                    user_info['is_admin'] = users.is_admin
                    user_info['is_staff'] = users.is_staff

                    return Response({"user_info": user_info, "user_settings": user_settings_info, "org_setting": org_settings_info, "status": status.HTTP_200_OK})
                except:
                    return Response({'messege': 'account not found', 'status': 400})
        else:
            return Response({'messege': 'Access denied', 'status': 400})
