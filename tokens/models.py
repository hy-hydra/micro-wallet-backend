from django.db import models
from user.models import User
# Create your models here.
from dry_rest_permissions.generics import authenticated_users


class Token(models.Model):
    name = models.CharField(max_length=100)      # Wrape USDT
    symbol = models.CharField(max_length=20)     # symbol like USDT
    contract = models.CharField(unique=True)  # Token contract address
    decimals = models.IntegerField(default=8)  # 8 | 12 | 6 | 18 etc
    sell_price = models.FloatField(default=1)
    buy_price = models.FloatField(default=1)
    icon = models.CharField(max_length=255)   # should be icon image name
    type = models.CharField(default='ERC20', max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name


class UserToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING)
    token = models.ForeignKey(Token, on_delete=models.DO_NOTHING)
    balance = models.FloatField(default=0)
    # Balance in real token contract
    prev_balance = models.FloatField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.user.email
