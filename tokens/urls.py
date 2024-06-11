from django.urls import path

from .views import TokenView, TokenViewForUser, GetUserTokenView, UserTokenBalanceView

urlpatterns = [
    path('tokenview', TokenView.as_view(), name="tokenview"),
    path('get_app_token', TokenViewForUser.as_view(), name="get_app_token"),
    path('get_user_tokens', GetUserTokenView.as_view(), name="get_user_tokens"),
    path('get_balanced_info', UserTokenBalanceView.as_view(), name="get_balanced_info"),
]
