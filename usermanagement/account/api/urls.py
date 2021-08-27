from django.urls import include, path
from account.api.views import(
    #     PasswordTokenCheckAPI,
    #     RequestPasswordResetEmail,
    #     SetNewPasswordAPIView,


    PasswordTokenCheckAPI,
    RequestPasswordResetEmail,
    SetNewPasswordAPIView,
    UserInfoView,
    UserListView,
    UserUpdate,
    registration_view,
    ObtainAuthTokenView,
    does_account_exist_view,
    ChangePasswordView,
)
from rest_framework.authtoken.views import obtain_auth_token
from account.api.views import NewUserCreate, UserDelete
from django.conf.urls import url


app_name = 'account'

urlpatterns = [
    path('validate', does_account_exist_view,
         name="validate"),
    path('change-password', ChangePasswordView.as_view(), name="change_password"),
    path('login', ObtainAuthTokenView.as_view(), name="login"),
    path('register', registration_view, name="register"),
    path('', NewUserCreate.as_view(), name="usercreate"),
    path('list', UserListView.as_view(), name="userlist"),
    path('info/<int:pk>', UserInfoView.as_view(), name="userinfo"),
    path('<int:pk>', UserUpdate.as_view(), name="userupdate"),
    path('<int:pk>', UserDelete.as_view(), name="userdelete"),

]