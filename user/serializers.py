from django.contrib.auth import get_user_model
from rest_framework import serializers
from tokens.serializer import UserTokenSerializer

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('id', 'email', 'password', 'username')


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('id', 'email', 'password', 'otp_enabled', 'otp_verified')


class UserOTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'password', 'email', 'otp_enabled',
                  'otp_verified', 'otp_base32', 'otp_auth_url']

        extra_kwargs = {
            'password': {'write_only': True}
        }


class AccountSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'first_name', 'last_name', 'password', 'birth_date', 'country', 'city', 'postal_code', 'present_address', 'deposit_addr', 'otp_enabled', 'otp_verified',
                  'otp_base32', 'otp_auth_url', 'referral_code', 'refer_count', 'refer_enabled', 'tier_level', 'created_at', 'updated_at', 'is_active', 'is_staff')

        extra_kwargs = {
            'password': {'write_only': True}
        }


class AccontCreationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'first_name',
                  'last_name', 'refer_enabled', 'otp_enabled', 'parent_email')

        extra_kwargs = {}


class AppUserSerializer(serializers.ModelSerializer):

    usertoken_set = UserTokenSerializer(many=True, read_only=True)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        depth = 2
        fields = '__all__'

class ReferralUserSummarySerializer(serializers.Serializer):        
    iqdt_payout = serializers.FloatField()
    children_iqdt_payout = serializers.FloatField()
    id = serializers.IntegerField()
    username = serializers.CharField()
    referral_code = serializers.CharField()
    date = serializers.DateTimeField()   
    has_child = serializers.BooleanField()
    tier = serializers.IntegerField()
