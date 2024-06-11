import random
import json
from datetime import datetime
import os
import secrets
import pyotp, base64

from django.db.models import F, Q
from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate, login, hashers
from django.utils.http import urlsafe_base64_decode
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
# force_text on older versions of Django
from django.utils.encoding import force_str, force_bytes

from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from eth_account import Account

from user.serializers import UserSerializer, UserOTPSerializer, AccountSerializer, UserLoginSerializer, AccontCreationSerializer, ReferralUserSummarySerializer
from referral_system.serializers import ReferralTierSerializer, ReferralTierLevelSerializer
from user.models import User, UserWalletCredential
from tokens.models import UserToken, Token
from transaction.models import Swap
from transaction.serializer import SwapTxSerializer
from transaction.utils import TransactionUtils
from referral_system.models import ReferralTierModel, ReferralTierLevelModel
from user.token import token_generator

from .utils import UserViewUtils, encrypt_private_key, decrypt_private_key
# Create your views here.


class UserRegisterationView(APIView):

    permission_classes = (AllowAny, )
    authentication_classes = ()
    serializer_class = UserSerializer

    def get(self, request):
        # encryption_key = os.urandom(32)
        cre = UserWalletCredential.objects.get(id=38)
        # encrypted_private_key = encrypt_private_key(cre.private_key, encryption_key)
        # cre.private_key = encrypted_private_key
        # cre.encryption_key = encryption_key
        # cre.save()
        decrypted_system_private_key = decrypt_private_key(eval(cre.private_key), eval(cre.encryption_key))

        return Response({'data': decrypted_system_private_key}, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)        
        if serializer.is_valid():
            req_refer_code = request.query_params.get('code')            
            if req_refer_code:
                system_admin = get_object_or_404(User, email=settings.SYSTEM_ADMIN_EMAIL)
                employer = get_object_or_404(User, referral_code=req_refer_code)
                if employer.refer_enabled:
                    try:                        
                        employer_refer_model = ReferralTierModel.objects.get(child=employer)
                        if employer_refer_model.tier_level >= 6:
                            employer.refer_enabled = False
                            employer.save()
                            return Response(
                                        {
                                            "data": None,
                                            "message": "Employer approached maximum limit of referral"
                                        },
                                        status=status.HTTP_400_BAD_REQUEST
                                    )
                        else:
                            refer_tier_level = employer_refer_model.tier_level + 1
                    except ReferralTierModel.DoesNotExist:
                        if employer.email == system_admin.email:
                            refer_tier_level = 1
                        else:
                            raise TypeError('Something went wrong with system admin or refer model database')

                    ref_code = UserViewUtils.get_random_string(self, 15)

                    priv = secrets.token_hex(32)
                    private_key = "0x" + priv
                    encryption_key = os.urandom(32)
                    encrypted_private_key = encrypt_private_key(private_key, encryption_key)
                    acct = Account.from_key(private_key)                
                    user = User.objects.create_user(
                        **serializer.validated_data, referral_code=ref_code, parent_email=employer.email, deposit_addr=acct.address, tier_level=refer_tier_level)
                    # Mail verification section
                    subject = 'Activate Your Account'
                    context = {
                        'username': user.username,
                        'email': user.email,
                        'domain': settings.DOMAIN,
                        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                        'token': token_generator.make_token(user),
                    }
                    message = render_to_string('users/activate_account.html', context)

                    UserViewUtils.send_mail([user.email], subject, message)
                    UserWalletCredential.objects.create(user=user, private_key=encrypted_private_key, encryption_key=encryption_key, public_key=acct.address)
                    ReferralTierModel.objects.create(parent=employer, child=user, tier_level=refer_tier_level)
                    return Response(
                        {
                            "data": None,
                            "message": "Created new account and mail verification has been sent."
                        },
                        status=status.HTTP_201_CREATED
                    )                                 
                else:
                    return Response(
                        {
                            "data": None,
                            "message": "Inviter is disabled to refer"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )  
            else:
                return Response(
                    {
                        "data": None,
                        "message": "Sign up is only possible by referral"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )          
        else:
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )


class UserLoginView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()
    serializer_class = UserLoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, partial=True)
        if serializer.is_valid():
            email = serializer["email"].value
            username = User.objects.get(email=email)
            password = request.data["password"]

            user = authenticate(request, username=username,
                                email=email, password=password)

            if user is not None:
                user.otp_verified = False
                user.save()
                if hasattr(user, 'is_active'):
                    login(request, user)
                    refresh = RefreshToken.for_user(user)
                    data = {
                        "tokenObj": {
                            'refresh': str(refresh),
                            'access': str(refresh.access_token),
                        },
                        "user": self.serializer_class(instance=user).data
                    }
                    return Response(
                        data=data,
                        status=status.HTTP_200_OK
                    )
                else:
                    return Response(
                        {
                            "error": "Email not verified",
                        },
                        status=401,
                    )
            else:
                return Response(
                    {
                        "error": "Invalid email or password",
                    },
                    status=400,
                )
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLogoutView(APIView):
    permission_classes = (AllowAny, )

    def delete(self, request):
        user = request.user
        user.otp_verified = False
        user.save()
        return Response({
            'data': None,
            'message': 'Logout successfully'
        },
            status=status.HTTP_200_OK)


class UserPasswordView(APIView):
    permission_classes = (IsAuthenticated, )
    serializer_class = UserSerializer
    # Reset password

    def put(self, request):
        user = request.user
        new_password = request.data['new_password']
        old_password = request.data['old_password']
        matched = hashers.check_password(old_password, user.password)
        if matched:
            user.password = hashers.make_password(new_password)
            user.save()
            return Response(
                {
                    'data': None,
                    'message': 'Password has been updated successfully'
                },
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {
                    'data': None,
                    'message': 'Bad Request'
                },
                status=status.HTTP_400_BAD_REQUEST
            )

class UserResetPasswordView(APIView):
    permission_classes = (AllowAny, )
    serializer_class = UserSerializer
    # Reset password

    def get(self, request, uidb64, token):        
        new_password = request.query_params.get('new_password')
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)            
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and token_generator.check_token(user, token):
            user.password = hashers.make_password(new_password)
            user.save()
            return Response(
                {
                    'data': 'success',
                    'message': 'Successfully reset password'
                },
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {
                    'data': None,
                    'message': 'Failed to verify your email'
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        

class ForgotPasswordView(APIView):
    permission_classes = (AllowAny, )
    serializer_class = UserSerializer
    def get(self, request):
        email = request.query_params.get('email')
        serializer = self.serializer_class(data={email: email}, partial=True)
        if serializer.is_valid():
            try:
                user = User.objects.get(email=email)
                # Mail verification section
                current_site = get_current_site(request)
                subject = 'Reset Your Password'
                message = render_to_string(
                    'users/forgot_password.html',
                    {
                        'user': user,
                        'domain': current_site.domain,
                        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                        'token': token_generator.make_token(user),
                    }
                )

                UserViewUtils.send_mail([user.email], subject, message)

            except User.DoesNotExist:
                raise TypeError('User is not found')
            return Response(
                {
                    'data': None,
                    'message': "Reset password mail has been sent"
                },
                status=status.HTTP_200_OK
            )
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserAccountView(APIView):
    permission_classes = (IsAuthenticated, )
    serializer_class = AccountSerializer

    def get(self, request):
        user = request.user
        if user.refer_enabled is not True:
            del user.referral_code
        data = self.serializer_class(instance=user, partial=True).data
        return Response(
            {
                'data': data,
                'message': 'Get user information successfully'
            },
            status=status.HTTP_200_OK
        )


class ConfirmEmailView(APIView):
    permission_classes = (AllowAny, )

    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            login(request, user)
        return Response(
            {
                'data': None,
                "message": "Successfully verified email and activated account"
            },
            status=status.HTTP_200_OK
        )

class ActivateView(APIView):
    permission_classes = (AllowAny, )    

    # Custom get method
    def get(self, request, uidb64, token):

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            login(request, user)
            return Response({
                'data': None,
                'message': 'success'
            })
        else:
            return Response(
                {
                    'data': None,
                    'message': 'Failed to verify your email'
                },
                status=status.HTTP_400_BAD_REQUEST
            )


class AdminUsersView(APIView):
    permission_classes = (IsAdminUser, )
    serializer_class = AccontCreationSerializer

    def get(self, request):
        app_users = User.objects.all().exclude(password='').values()        
        # AppUserSerializer(instance=app_users, many=True).data
        return Response(
            {
                'data': app_users,
                'message': 'Retrieved all app users.'
            },
            status=status.HTTP_200_OK
        )

    def put(self, request):
        user_id = request.query_params.get('user_id')
        user = get_object_or_404(User, id=user_id)
        data = request.data

        serializer = self.serializer_class(
            instance=user, data=data, partial=True)
        
        if serializer.is_valid():
           serializer.save()
           return Response(
                {
                    'data': self.serializer_class(instance=user).data,
                    'message': 'Updated user successfully'
                }
           )
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request):
        employer = get_object_or_404(User, email=request.data['parent_email'])
        if employer.refer_enabled:
            try:
                system_admin = get_object_or_404(User, email=settings.SYSTEM_ADMIN_EMAIL)
                employer_refer_model = ReferralTierModel.objects.get(child=employer)
                if employer_refer_model.tier_level >= 6:
                    employer.refer_enabled = False
                    employer.save()
                    return Response(
                                {
                                    "data": None,
                                    "message": "Employer approached maximum limit of referral"
                                },
                                status=status.HTTP_400_BAD_REQUEST
                            )
                else:
                    refer_tier_level = employer_refer_model.tier_level + 1
            except ReferralTierModel.DoesNotExist:
                if employer.email == system_admin.email:
                    refer_tier_level = 1
                else:
                    raise TypeError('Something went wrong with system admin or refer model database')

            ref_code = UserViewUtils.get_random_string(self, 15)
            priv = secrets.token_hex(32)
            private_key = "0x" + priv
            acct = Account.from_key(private_key)
            serializer = self.serializer_class(data=request.data)                
            if serializer.is_valid():
                user = User.objects.create_user(
                    **serializer.validated_data, referral_code=ref_code, deposit_addr=acct.address, password='12345678')            
                UserWalletCredential.objects.create(user=user, private_key=private_key, public_key=acct.address)
                ReferralTierModel.objects.create(parent=employer, child=user, tier_level=refer_tier_level)
                
                return Response(
                    {
                        'data': self.serializer_class(instance=user).data,
                        "message": "Created User successfully"
                    },
                    status=status.HTTP_201_CREATED
                )
            else:
                return Response(
                    serializer.errors, status=status.HTTP_400_BAD_REQUEST
                )
        else:
            return Response(
                {
                    "data": None,
                    "message": "Inviter is disabled to refer"
                },
                status=status.HTTP_400_BAD_REQUEST
            )  

    def delete(self, request):
        user_id = request.query_params.get('user_id')
        try:
            user = User.objects.get(id=user_id)
            if user.is_active:
                user.is_active = False
            else:
                user.is_active = True
            user.save()
        except User.DoesNotExist:
            raise TypeError("User does not exist")

        return Response(
            {
                'data': None,
                "message": "Successfully deactivated user"
            }
        )


class AdminUserDetailView(APIView):
    permission_classes = (IsAdminUser, )
    serializer_class = AccountSerializer

    def get(self, request):
        user_id = request.query_params.get('user_id')
        user = User.objects.get(id=user_id)
        try:
            user_token = UserToken.objects.filter(user=user).values('balance', type=F('token__type'), name=F('token__name'), symbol=F('token__symbol'), decimals=F(
                'token__decimals'), contract=F('token__contract'), sell_price=F('token__sell_price'), buy_price=F('token__buy_price'), icon=F('token__icon'))
        except UserToken.DoesNotExist:
            raise TypeError('User does not have token')

        try:
            token_IQDT = Token.objects.get(name='IQDT')
        except Token.DoesNotExist:
            raise TypeError('No token found')

        tier_list = ReferralTierModel.objects.filter(parent=user)
        tier_level_values = ReferralTierLevelModel.objects.first()
        rewards = 0
        if len(tier_list) > 0:
            for tier_item in tier_list:
                start_date = datetime.now().strftime('%Y-%m-%d')
                end_date = TransactionUtils.last_date_of_month(start_date)
                payout_tx = Swap.objects.filter(user=tier_item.child,
                                                get_token=token_IQDT, timestamp__range=(str(start_date), str(end_date)))
                payout = 0
                for tx_item in payout_tx:
                    payout += tx_item.get_amount

                rewards = payout * tier_level_values['tier_'+str({tier_item.tier_level})] / 100

        return Response(
            {
                'data': {
                    'user': self.serializer_class(instance=user).data,
                    'user_token': list(user_token),
                    'rewards': rewards
                },
                "message": "Successfully retrieved user detail information"
            },
            status=status.HTTP_200_OK
        )


class GenerateOTP(APIView):
    serializer_class = UserOTPSerializer
    queryset = User.objects.all()

    def post(self, request):
        data = request.data
        user_id = data.get('user_id', None)
        email = data.get('email', None)

        user = User.objects.filter(id=user_id).first()
        if user == None:
            return Response({"status": "fail", "message": f"No user with Id: {user_id} found"}, status=status.HTTP_404_NOT_FOUND)

        otp_base32 = pyotp.random_base32()
        otp_auth_url = pyotp.totp.TOTP(otp_base32).provisioning_uri(
            name=email.lower(), issuer_name="Marcowallet.io")

        user.otp_auth_url = otp_auth_url
        user.otp_base32 = otp_base32
        user.save()

        return Response({'base32': otp_base32, "otpauth_url": otp_auth_url})


class VerifyOTP(APIView):
    serializer_class = UserOTPSerializer
    queryset = User.objects.all()

    def post(self, request):
        data = request.data
        user_id = data.get('user_id', None)
        otp_token = data.get('token', None)
        user = User.objects.filter(id=user_id).first()
        if user == None:
            return Response({"status": "fail", "message": f"No user with Id: {user_id} found"}, status=status.HTTP_404_NOT_FOUND)

        totp = pyotp.TOTP(user.otp_base32)
        if not totp.verify(otp_token):
            return Response({"status": "fail", "message": "Token is invalid"}, status=status.HTTP_400_BAD_REQUEST)
        user.otp_enabled = True
        user.otp_verified = True
        user.save()
        serializer = self.serializer_class(user)

        return Response({'otp_verified': True, "user": serializer.data})


class ValidateOTP(APIView):
    permission_classes = (AllowAny, )
    serializer_class = UserOTPSerializer
    queryset = User.objects.all()

    def post(self, request):
        message = "Token is invalid or user doesn't exist"
        data = request.data
        user_id = data.get('user_id', None)
        otp_token = data.get('token', None)
        user = User.objects.filter(id=user_id).first()
        if user == None:
            return Response({"status": "fail", "message": f"No user with Id: {user_id} found"}, status=status.HTTP_404_NOT_FOUND)

        totp = pyotp.TOTP(user.otp_base32)
        if not totp.verify(otp_token, valid_window=1):
            return Response({"status": "fail", "message": message}, status=status.HTTP_400_BAD_REQUEST)
        user.otp_verified = True
        user.save()
        refresh = RefreshToken.for_user(user)

        return Response({
                        'otp_valid': True, 
                         "tokenObj": {
                            'refresh': str(refresh),
                            'access': str(refresh.access_token),
                        }
                        })


class DisableOTP(APIView):
    serializer_class = UserOTPSerializer
    queryset = User.objects.all()

    def post(self, request):
        data = request.data
        user_id = data.get('user_id', None)

        user = User.objects.filter(id=user_id).first()
        if user == None:
            return Response({"status": "fail", "message": f"No user with Id: {user_id} found"}, status=status.HTTP_404_NOT_FOUND)

        user.otp_enabled = False
        user.otp_verified = False
        user.otp_base32 = None
        user.otp_auth_url = None
        user.save()
        serializer = self.serializer_class(user)

        return Response({'otp_disabled': True, 'user': serializer.data})


class ReferralTierView(APIView):
    permission_classes = (IsAdminUser, )
    serializer_class = ReferralTierLevelSerializer

    def get(self, request):        
        tier_level_obj = ReferralTierLevelModel.objects.first()
        return Response(
            {
                'tier_data': ReferralTierLevelSerializer(instance=tier_level_obj).data,
                'message': "Successfully retreived refer information"
            },
            status=status.HTTP_200_OK
        )

    def put(self, request):
        data = request.data
        tier_level_obj = ReferralTierLevelModel.objects.first()
        serializer = self.serializer_class(instance=tier_level_obj, data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    'data': None,
                    'message': 'Successfully updated tier level'
                },
                status=status.HTTP_200_OK
            )
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ReferralUserListByAdminView(APIView):
    permission_classes = (IsAdminUser, )

    def get(self, request):
        refer_list = ReferralTierModel.objects.all().order_by('tier_level')
        return Response(
            {
                'data': ReferralTierSerializer(instance=refer_list, many=True).data,
                'message': "Successfully retreived refer information"
            },
            status=status.HTTP_200_OK
        )


class ReferralUserListView(APIView):
    permission_classes = (IsAuthenticated, )

    def get(self, request):
        def getChildren(refer_list, children_refer_list):            
            all_children_refer_list = children_refer_list
            all_children_refer_list += refer_list
            for refer_list_item in refer_list:
                sub_refer_list = ReferralTierModel.objects.filter(parent=refer_list_item.child)                
                if len(sub_refer_list) > 0:
                    getChildren(sub_refer_list, all_children_refer_list)
            return all_children_refer_list
        
        first_refer_list = ReferralTierModel.objects.filter(parent=request.user)
        all_children_list = [] if len(first_refer_list) == 0 else getChildren(first_refer_list, [])
        data = ReferralTierSerializer(instance=all_children_list, many=True).data
        return Response(
            {
                'data': data,
                'message': "Successfully retreived refer information"
            },
            status=status.HTTP_200_OK
        )


class ReferralUserSummaryByAdminView(APIView):
    permission_classes = (IsAdminUser, )

    def get(self, request):
        target_month = request.query_params.get('target_month')
        selected_parent_id = request.query_params.get('selected_parent_id')                

        if target_month:
            start_date = '2023-01-01'
            end_date = TransactionUtils.last_date_of_month(target_month)
            try:
                token_IQDT = Token.objects.get(name='IQDT')
            except Token.DoesNotExist:
                raise TypeError('No token found')
            
            payout_tx = Swap.objects.filter(get_token=token_IQDT, timestamp__range=(str(start_date), str(end_date)))            
            
            if selected_parent_id:
                selected_parent = get_object_or_404(User, id=selected_parent_id)
                refer_tier_list = ReferralTierModel.objects.filter(parent=selected_parent, created_at__range=(str(start_date), str(end_date)))
            else:
                refer_tier_list = ReferralTierModel.objects.filter(tier_level=1, created_at__range=(str(start_date), str(end_date)))

            def getIQDTPayout(item_iqdt_payout, child_referral_list):
                iqdt_payout=item_iqdt_payout
                if len(child_referral_list) > 0:                    
                    for child_list_1_item in child_referral_list:
                        child_list_1_payout_tx = payout_tx.filter(user=child_list_1_item.child)
                        if len(child_list_1_payout_tx) > 0:
                            for child_list_1_payout_tx_item in child_list_1_payout_tx:                                
                                iqdt_payout += child_list_1_payout_tx_item.get_amount                                
                                child_list_2 = ReferralTierModel.objects.filter(parent=child_list_1_item.child)                
                                getIQDTPayout(iqdt_payout, child_list_2)
                        else:
                            return iqdt_payout
                    return iqdt_payout
                else:
                    return iqdt_payout

            grouped_data = []
            total_iqdt_bought_amount = 0
            for refer_tier in refer_tier_list:                
                user_iqdt_payout = 0
                children_iqdt_payout = 0
                                                
                user_payout_tx = payout_tx.filter(user=refer_tier.child)
                for payout_tx_item in user_payout_tx:
                    user_iqdt_payout += payout_tx_item.get_amount
                
                child_list_1 = ReferralTierModel.objects.filter(parent=refer_tier.child)
                children_iqdt_payout = getIQDTPayout(0, child_list_1) 

                tier_child_children = ReferralTierModel.objects.filter(parent=refer_tier.child)
            
                grouped_data_item={
                'id': refer_tier.child.id,
                'username': refer_tier.child.username,
                'referral_code': refer_tier.child.referral_code,
                'date': refer_tier.child.created_at,
                'iqdt_payout': user_iqdt_payout * token_IQDT.buy_price,
                'children_iqdt_payout': children_iqdt_payout * token_IQDT.buy_price,
                'has_child': True if len(tier_child_children) > 0 else False,
                'tier': refer_tier.tier_level
                }
                
                total_iqdt_bought_amount += children_iqdt_payout                
                grouped_data.append(grouped_data_item)

            return Response(
                {
                    'data': ReferralUserSummarySerializer(instance=grouped_data, many=True).data,
                    'total_iqdt': total_iqdt_bought_amount * token_IQDT.buy_price,
                    'message': 'Successfully retrieved referral summary data'
                }
            )

        else:
            return Response(
                {
                    'data': None,
                    "message": "Bad request"
                }, status=status.HTTP_400_BAD_REQUEST)


class ReferralUserSummaryView(APIView):
    permission_classes = (IsAuthenticated, )

    def get(self, request):
        target_month = request.query_params.get('target_month')
        selected_parent_id = request.query_params.get('selected_parent_id')


        if target_month:
            start_date = '2023-01-01'
            end_date = TransactionUtils.last_date_of_month(target_month)
            try:
                token_IQDT = Token.objects.get(name='IQDT')                
            except Token.DoesNotExist:
                raise TypeError('No token found')

            payout_tx = Swap.objects.filter(
                get_token=token_IQDT, timestamp__range=(str(start_date), str(end_date)))            
            if selected_parent_id:
                selected_parent = get_object_or_404(User, id=selected_parent_id)
                requested_refer_user = selected_parent
            else:
                requested_refer_user = request.user
            refer_tier_list = ReferralTierModel.objects.filter(parent=requested_refer_user, created_at__range=(str(start_date), str(end_date)))

            def getIQDTPayout(item_iqdt_payout, child_referral_list):
                iqdt_payout=item_iqdt_payout
                if len(child_referral_list) > 0:                    
                    for child_list_1_item in child_referral_list:
                        child_list_1_payout_tx = payout_tx.filter(user=child_list_1_item.child)
                        if len(child_list_1_payout_tx) > 0:
                            for child_list_1_payout_tx_item in child_list_1_payout_tx:                                
                                iqdt_payout += child_list_1_payout_tx_item.get_amount                                
                                child_list_2 = ReferralTierModel.objects.filter(parent=child_list_1_item.child)                
                                getIQDTPayout(iqdt_payout, child_list_2)
                        else:
                            return iqdt_payout
                    return iqdt_payout
                else:
                    return iqdt_payout

            grouped_data = []
            total_iqdt_bought_amount = 0
            for refer_tier in refer_tier_list:
                user_iqdt_payout = 0                
                user_payout_tx = payout_tx.filter(user=refer_tier.child)
                for payout_tx_item in user_payout_tx:
                    user_iqdt_payout += payout_tx_item.get_amount
                
                child_list_1 = ReferralTierModel.objects.filter(parent=refer_tier.child)
                children_iqdt_payout=getIQDTPayout(0, child_list_1)

                tier_child_children = ReferralTierModel.objects.filter(parent=refer_tier.child)

                grouped_data_item={
                    'id': refer_tier.child.id,
                    'username': refer_tier.child.username,
                    'referral_code': refer_tier.child.referral_code,
                    'date': refer_tier.child.created_at,
                    'iqdt_payout': user_iqdt_payout * token_IQDT.buy_price,
                    'children_iqdt_payout': children_iqdt_payout * token_IQDT.buy_price,
                    'has_child': True if len(tier_child_children) > 0 else False,
                    'tier': refer_tier.tier_level
                }
                total_iqdt_bought_amount += children_iqdt_payout
                grouped_data.append(grouped_data_item)

            return Response(
                {
                    'data': ReferralUserSummarySerializer(instance=grouped_data, many=True).data,
                    'total_iqdt': total_iqdt_bought_amount * token_IQDT.buy_price,
                    'message': 'Successfully retrieved referral summary data'
                }
            )

        else:
            return Response(
                {
                    'data': None,
                    "message": "Bad request"
                }, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        user_id_name = request.query_params.get('user_id_name')
        user_ref_code = request.query_params.get('user_ref_code')                
        
        if user_id_name and user_ref_code:
            users = User.objects.filter(Q(id=user_id_name) | Q(username=user_id_name)).filter(referral_code=user_ref_code)
        elif user_id_name:
            if user_id_name.isnumeric():
                users = User.objects.filter(id=user_id_name)
            else:
                users = User.objects.filter(username=user_id_name)
        elif user_ref_code:
            users = User.objects.filter(referral_code=user_ref_code)
        else:
            return Response({
                'data': None,
                'message': 'Bad Request'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        def getBreadcrumbs(child, currentBreadcrumbs)->list:
            breadCrumbs = currentBreadcrumbs
            try:                
                user_refer_tier = ReferralTierModel.objects.get(child=child)
                if user_refer_tier.parent.email == settings.SYSTEM_ADMIN_EMAIL:
                    return list(breadCrumbs)
                else:
                    breadCrumbs.append({
                        'id': user_refer_tier.parent.id,
                        'username': user_refer_tier.parent.username
                    })
                    return getBreadcrumbs(user_refer_tier.parent, breadCrumbs)
            except ReferralTierModel.DoesNotExist:
                return breadCrumbs            


        if len(users) > 0:
            breadCrumbsList = getBreadcrumbs(users[0], [])
            breadCrumbsList.reverse()
            return Response({
                'data': breadCrumbsList
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'data': None,
            }, status=status.HTTP_404_NOT_FOUND)
        
