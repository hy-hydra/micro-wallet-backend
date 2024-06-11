from django.urls import path
from .views import UserLoginView, ForgotPasswordView, UserRegisterationView, GenerateOTP, VerifyOTP, ValidateOTP, DisableOTP, UserAccountView, AdminUsersView, ActivateView, ConfirmEmailView, AdminUserDetailView, UserPasswordView, ReferralTierView, ReferralUserListView, UserLogoutView, UserResetPasswordView, ReferralUserSummaryView, ReferralUserListByAdminView, ReferralUserSummaryByAdminView

urlpatterns = [
    path('login', UserLoginView.as_view(), name='login'),
    path('register', UserRegisterationView.as_view(), name='register'),
    path('me', UserAccountView.as_view(), name='account me'),
    path('verifyEmail', ConfirmEmailView.as_view(), name="verify email"),
    path('change_password', UserPasswordView.as_view(), name="Reset password"),
    path('reset_password/<uidb64>/<token>/', UserResetPasswordView.as_view(), name="Reset Password"),
    path('forgot_password', ForgotPasswordView.as_view(), name="Forgot password"),
    path('activate/<uidb64>/<token>/', ActivateView.as_view(), name="activate"),
    path('otp/generate', GenerateOTP.as_view()),
    path('otp/verify', VerifyOTP.as_view()),
    path('otp/validate', ValidateOTP.as_view()),
    path('otp/disable', DisableOTP.as_view()),
    path('logout', UserLogoutView.as_view(), name="logout"),
    # admin
    path('app_user', AdminUsersView.as_view(), name='admin_app_user'),
    path('app_user/detail', AdminUserDetailView.as_view(),
         name='admin_app_user_detail'),
    path('referral_tier', ReferralTierView.as_view(), name='refer_tier_list'),
    path('user_refer_list', ReferralUserListView.as_view(), name='refer_tier_list'),
    path('user_refer_summary', ReferralUserSummaryView.as_view(), name='refer_tier_summary'),
    path('user_refer_list_by_admin', ReferralUserListByAdminView.as_view(), name='user_refer_list_by_admin'),
    path('user_refer_summary_by_admin', ReferralUserSummaryByAdminView.as_view(), name='refer_tier_summary')
]
