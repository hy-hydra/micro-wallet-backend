from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from django.utils.translation import gettext_lazy as _
# Create your models here.


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractUser, PermissionsMixin):
    birth_date = models.CharField(max_length=50)
    country = models.CharField(max_length=50)
    city = models.CharField(max_length=50)
    postal_code = models.CharField(max_length=20)
    present_address = models.CharField(max_length=255)
    # Email verification status
    # wallet information
    deposit_addr = models.CharField(max_length=100)

    # Referral code
    referral_code = models.CharField(max_length=100, unique=True)
    refer_count = models.IntegerField(default=0)
    tier_level = models.IntegerField(default=0)
    # is able to refer
    refer_enabled = models.BooleanField(default=False)
    parent_email = models.EmailField(_("parent email address"), blank=True)

    # Two factor authentication enable status
    otp_enabled = models.BooleanField(default=False)
    otp_verified = models.BooleanField(default=False)
    otp_base32 = models.CharField(max_length=255, null=True)
    otp_auth_url = models.CharField(max_length=255, null=True)

    # Withdrawal mail code
    mail_code = models.CharField(max_length=255, null=True)

    # IQDT Bought amount
    iqdt_payout_amount = models.FloatField(default=0)
    # Referral reward
    reward_amount = models.FloatField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()


class UserWalletCredential(models.Model):
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING)
    public_key = models.CharField(max_length=50, unique=True)
    private_key = models.TextField(unique=True)
    encryption_key = models.TextField(default='')
    tx_count = models.IntegerField(default=0)    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.public_key
