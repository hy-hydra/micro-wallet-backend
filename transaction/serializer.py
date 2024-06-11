from django.db import models
from rest_framework import serializers

from .models import DepositWithdraw, Transfer, Swap
from user.serializers import UserSerializer
from tokens.serializer import TokenSerializer


class DepositTokenSerializer(serializers.Serializer):
    class Meta:
        model = DepositWithdraw
        fields = ('token_id', 'amount', 'direct')


class WithdrawTokenSerializer(serializers.Serializer):
    class Meta:
        model = DepositWithdraw
        fields = ('withdraw_addr', 'token_id', 'amount', 'direct')


class TransferSerializer(serializers.Serializer):
    class Meta:
        model = Transfer
        fields = ('reciever_email', 'token_id', 'amount')


class TransferModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transfer
        fields = ('_from', '_to', 'token', 'amount', 'timestamp')


class SwapSerializer(serializers.Serializer):
    class Meta:
        model = Swap
        fiedls = ('send_token_id', 'send_amount', 'get_token_id')


class DepositTxSerializer(serializers.ModelSerializer):
    user = UserSerializer()
    token = TokenSerializer()

    class Meta:
        model = DepositWithdraw
        fields = '__all__'
        depth = 1


class TransferTxSerializer(serializers.ModelSerializer):
    _from = UserSerializer()
    _to = UserSerializer()
    token = TokenSerializer()

    class Meta:
        model = Transfer
        fields = '__all__'
        depth = 1


class SwapTxSerializer(serializers.ModelSerializer):
    user = UserSerializer()
    get_token = TokenSerializer()
    send_token = TokenSerializer()

    class Meta:
        model = Swap
        fields = '__all__'
        depth = 1
