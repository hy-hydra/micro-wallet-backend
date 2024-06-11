from django.db import models
from django.conf import settings

# Create your models here.

class ReferralTierModel(models.Model):
    parent = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='parent', on_delete=models.CASCADE)
    child = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='child',
                              on_delete=models.CASCADE)
    tier_level = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

class ReferralTierLevelModel(models.Model):
    tier_0 = models.FloatField(default=0)
    tier_1 = models.FloatField(default=5)
    tier_2 = models.FloatField(default=10)
    tier_3 = models.FloatField(default=15)
    tier_4 = models.FloatField(default=20)
    tier_5 = models.FloatField(default=25)