from django.urls import path

from .views import SwapView, TxHistoryView, WithdrawTokenView, TransferTokenView, DepositTokenView, TokenPayoutView, DepositTransactionView, WithdrawTransactionView, TransferTransactionView, SwapTransactionView, ApproveWithdrawalRequestView, AppTokenBalanceView, AutoCollectionView

urlpatterns = [
    path('swap_tokens', SwapView.as_view(), name='swap_tokens'),
    path('handle_withdrawal', ApproveWithdrawalRequestView.as_view(), name='withdraw_token'),
    path('request_withdraw', WithdrawTokenView.as_view(), name='withdraw_token'),
    path('transfer_token', TransferTokenView.as_view(), name='transfer_token'),
    path('refresh_user_token', DepositTokenView.as_view(),
         name='refresh_user_token'),
    path('token_payout', TokenPayoutView.as_view(), name='token_payout'),
    path('deposit_tx', DepositTransactionView.as_view(), name='deposit_tx'),
    path('withdraw_tx', WithdrawTransactionView.as_view(), name='withdraw_tx'),
    path('transfer_tx', TransferTransactionView.as_view(), name='transfer_tx'),
    path('swap_tx', SwapTransactionView.as_view(), name='swap_tx'),
    path('app_balances', AppTokenBalanceView.as_view(), name='app_balances'),
    path('tx_history', TxHistoryView.as_view(), name='transaction_histories'),
    path('auto_collect', AutoCollectionView.as_view(), name='auto_collect')
]
