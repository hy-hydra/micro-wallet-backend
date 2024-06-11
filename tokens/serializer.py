from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Token, UserToken

User = get_user_model()


class TokenSerializer(serializers.Serializer):
    name = serializers.CharField()
    symbol = serializers.CharField()
    contract = serializers.CharField()
    decimals = serializers.IntegerField()
    sell_price = serializers.FloatField()
    buy_price = serializers.FloatField()
    icon = serializers.CharField()

    class Meta:
        model = Token
        fields = ('name', 'symbol',
                  'decimals', 'contract', 'sell_price', 'buy_price', 'icon')


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    
    class Meta:
        model = User
        fields = ('id', 'email', 'username')



class UserTokenSerializer(serializers.ModelSerializer):
    user = UserSerializer()
    token = TokenSerializer()
    prev_balance = serializers.FloatField(default=0)

    class Meta:
        model = UserToken
        depth = 2
        fields = '__all__'
