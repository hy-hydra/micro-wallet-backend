from django.contrib import admin
from .models import Token, UserToken
# Register your models here.
admin.site.register(Token)
admin.site.register(UserToken)
