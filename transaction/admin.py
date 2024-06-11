from django.contrib import admin
from .models import Swap, Transfer, DepositWithdraw

# Register your models here.
admin.site.register(Swap)
admin.site.register(Transfer)
admin.site.register(DepositWithdraw)
