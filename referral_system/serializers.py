import secrets
from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import ReferralTierModel, ReferralTierLevelModel

User = get_user_model()

class ReferralUserSerializer(serializers.ModelSerializer):
    class Meta:        
        model = User
        fields = ('id', 'email', 'username', 'iqdt_payout_amount', 'referral_code', 'created_at')

class ReferralTierSerializer(serializers.ModelSerializer):
    parent = ReferralUserSerializer()
    child = ReferralUserSerializer()
    class Meta:
        model = ReferralTierModel
        fields = '__all__'
        depth = 1


class ReferralTierLevelSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReferralTierLevelModel
        fields = '__all__'
