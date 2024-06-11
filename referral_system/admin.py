from django.contrib import admin
from referral_system.models import ReferralTierModel, ReferralTierLevelModel

# Register your models here.
admin.site.register(ReferralTierModel)
admin.site.register(ReferralTierLevelModel)
