from django.db import models

from django.utils.translation import gettext_lazy as _
from user.models import User
from tokens.models import Token

# Create your models here.
# For transfer


class Transfer(models.Model):
    _from = models.ForeignKey(
        User, on_delete=models.DO_NOTHING, related_name="_from")
    _to = models.ForeignKey(
        User, on_delete=models.DO_NOTHING, related_name="_to")
    token = models.ForeignKey(Token, on_delete=models.DO_NOTHING)
    amount = models.FloatField(default=0)
    timestamp = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self._from.username


# For despoit and withraw


class DepositWithdraw(models.Model):
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING)
    token = models.ForeignKey(Token, on_delete=models.DO_NOTHING)
    amount = models.FloatField(default=0)
    # True mean Deposit, False is Withdraw
    direct = models.BooleanField(default=True)
    timestamp = models.DateTimeField(auto_now=True)
    # 0 is rejected, 1: pending, 2 approved
    status = models.IntegerField(default=1)
    withdraw_addr = models.CharField(max_length=50)

    def __str__(self) -> str:
        return self.user.username


# For swap


class Swap(models.Model):
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING)
    send_token = models.ForeignKey(
        Token, on_delete=models.DO_NOTHING, related_name="send_token")
    send_amount = models.FloatField()
    get_token = models.ForeignKey(
        Token, on_delete=models.DO_NOTHING, related_name="get_token")
    get_amount = models.FloatField()
    timestamp = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.user.username

class AutoCollectSetting(models.Model):
    is_auto = models.BooleanField(default=False)
    hardware_wallet = models.CharField(max_length=100, default='0x704fb53913ED94203C7AC626E3eBF8D64E583a17')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> bool:
        return self.is_auto