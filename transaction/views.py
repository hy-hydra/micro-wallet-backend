import time
from django.template.loader import render_to_string
from django.db.models import F, Q, Sum
from django.conf import settings
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status

from .models import Swap, DepositWithdraw, Transfer, AutoCollectSetting
from tokens.models import UserToken, Token
from user.models import User, UserWalletCredential
from .serializer import SwapSerializer, TransferSerializer, WithdrawTokenSerializer, TransferModelSerializer, DepositTxSerializer, TransferTxSerializer, SwapTxSerializer
from . import constant as CONSTANTS
from .utils import TransactionUtils
from user.utils import UserViewUtils, decrypt_private_key

from web3 import Web3
from web3.exceptions import InvalidTransaction, Web3Exception, ProviderConnectionError



# Create your views here.
web3 = Web3(Web3.HTTPProvider(CONSTANTS.JSON_RPC[settings.NETWORK]))


class DepositTokenView(APIView):
    permission_classes = (IsAuthenticated, )

    def get(self, request):
        user = request.user
        user_wallet = UserWalletCredential.objects.get(user=user) 
        app_tokens = Token.objects.all()
        if len(app_tokens) > 0:
            for token in app_tokens:
                token_contract = web3.eth.contract(
                    address=web3.to_checksum_address(token.contract), abi=CONSTANTS.TOKEN_ABI[settings.NETWORK])
                # returns int with balance, without decimals
                token_balance = token_contract.functions.balanceOf(
                    user_wallet.public_key).call({"from": web3.to_checksum_address(user_wallet.public_key)})
                try:
                    user_token = UserToken.objects.get(user=user, token=token)    
                    new_deposit_balance = token_balance / pow(10, token.decimals) - user_token.prev_balance
                    if new_deposit_balance > 0:
                        user_token.balance += new_deposit_balance
                        user_token.prev_balance = token_balance / pow(10, token.decimals)
                        user_token.save()
                        DepositWithdraw.objects.create(user=user, token=token, amount=new_deposit_balance, direct=True)
                        # Auto collection starts from here
                        collect_setting = AutoCollectSetting.objects.first()
                        if collect_setting and user.email != settings.SYSTEM_ADMIN_EMAIL:
                            if user_token.prev_balance > 1000 and user_token.token.name == 'USDT' and collect_setting.is_auto == True:
                                system_admin = User.objects.get(email=settings.SYSTEM_ADMIN_EMAIL)
                                system_credential = UserWalletCredential.objects.get(user=system_admin)
                                system_wallet_balance_wei = web3.eth.get_balance(system_credential.public_key)
                                system_wallet_balance = web3.from_wei(system_wallet_balance_wei, 'ether')
                                decrypted_system_private_key = decrypt_private_key(eval(system_credential.private_key), eval(system_credential.encryption_key))

                                eth_transaction = {
                                    "from": system_credential.public_key,
                                    "to": user_wallet.public_key,
                                    "value": web3.to_wei(0.005, "ether"),  # Convert amount to wei
                                    "gas": 21000,  # Standard gas limit for a simple transaction
                                    "gasPrice": web3.eth.gas_price,
                                    "nonce": web3.eth.get_transaction_count(system_credential.public_key),
                                }            
                                signed_transaction = web3.eth.account.sign_transaction(eth_transaction, decrypted_system_private_key)
                                
                                total_eth_amount_to_send = 0.005

                                if system_wallet_balance < total_eth_amount_to_send:
                                    raise ValueError("Insufficient balance in the sender address")

                                tx_hash = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
                                print(f"In deposit: Transaction sent. Transaction Hash: {tx_hash.hex()}")

                                time.sleep(10)

                                usdt_token = Token.objects.get(name='USDT')
                                usdt_token_contract = web3.eth.contract(address=web3.to_checksum_address(usdt_token.contract), abi=CONSTANTS.TOKEN_ABI[settings.NETWORK])
                                token_transaction = usdt_token_contract.functions.transfer(system_credential.public_key, int(user_token.prev_balance)).build_transaction({
                                    'chainId': CONSTANTS.CHAIN_ID[settings.NETWORK],
                                    'gas': web3.to_hex(CONSTANTS.GAS),
                                    'gasPrice': web3.to_wei('30', 'gwei'),
                                    'nonce': web3.eth.get_transaction_count(user_wallet.public_key)
                                })
                                decrypted_private_key = decrypt_private_key(eval(user_wallet['private_key']), eval(user_wallet['encryption_key']))
                                signed_token_transaction = web3.eth.account.sign_transaction(token_transaction, decrypted_private_key)
                                tx_hash = web3.eth.send_raw_transaction(signed_token_transaction.rawTransaction)
                                print(f"Transaction sent. Transaction Hash: {tx_hash.hex()}")     
                                
                                user_token.prev_balance = 0
                                user_token.save()

                except UserToken.DoesNotExist:
                    UserToken.objects.create(user=user, token=token, balance=token_balance / pow(10, token.decimals))

            user_token_list = UserToken.objects.filter(
                user=user).annotate(OriginalId=F('id')).values('balance', type=F('token__type'), name=F('token__name'), symbol=F('token__symbol'), decimals=F('token__decimals'), contract=F('token__contract'), sell_price=F('token__sell_price'), buy_price=F('token__buy_price'), icon=F('token__icon')).annotate(id=F('token__id'))
            return Response(
                {
                    'data': user_token_list,
                    "message": "Updated User token"
                },
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {
                    'data': None,
                    'message': 'No app token found, please register token'
                },
                status=status.HTTP_204_NO_CONTENT
            )


class WithdrawTokenView(APIView):
    permission_classes = (IsAuthenticated, )
    serializer_class = WithdrawTokenSerializer

    def put(self, request):
        user = request.user
        mail_code = UserViewUtils.get_random_string(self, 6)

        context = {
            'username': user.username,
            'code': mail_code
        }

        message = render_to_string('transaction/withdraw.html', context)
        
        UserViewUtils.send_mail([user.email], 'Your Withdrawal Code', message)

        user.mail_code = mail_code
        user.save()

        return Response({
            'data': None,
            'message': 'Withdrawal confirmation code has been sent to the email'
        })


    def post(self, request):
        mail_code = request.query_params.get('mail_code')
        user = request.user
        serializer = self.serializer_class(data=request.data)
        if len(mail_code) == 6 and mail_code == user.mail_code:
            if serializer.is_valid():            
                token = Token.objects.get(id=request.data['token_id'])
                user_token = UserToken.objects.get(user=user, token=token)
                fee = round(15 / user_token.token.sell_price, 2)
                if user_token.balance >= request.data['amount'] + fee:
                    if web3.is_address(request.data['withdraw_addr']):
                        DepositWithdraw.objects.create(
                            user=user, token=token, amount=request.data['amount'], status=1, direct=False, withdraw_addr=request.data['withdraw_addr'])
                        user_token.balance -= request.data['amount'] + fee
                        user_token.save()
                        return Response(
                            {
                                'data': None,
                                'message': 'Successfully requested withdrawal'
                            },
                            status=status.HTTP_200_OK
                        )
                    else:
                        return Response(
                            {
                                "data": None,
                                "message": "The given address is not valid"
                            },
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {
                            'data': None,
                            'message': 'Insufficient fund'
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                return Response(
                    serializer.errors, status=status.HTTP_400_BAD_REQUEST
                )
        else:
            return Response(
                    {
                        'data': None,
                        'message': 'Withdrawal code is invalid'
                    },
                    status=status.HTTP_400_BAD_REQUEST
            )


class ApproveWithdrawalRequestView(APIView):
    permission_classes = (IsAdminUser, )

    def put(self, request):
        request_id = request.query_params.get('request_id')        
        withdraw_request = DepositWithdraw.objects.get(id=request_id)
        token = withdraw_request.token
        withdraw_addr = withdraw_request.withdraw_addr
        # declaring the token contract
        token_contract = web3.eth.contract(            
            address=web3.to_checksum_address(token.contract), abi=CONSTANTS.TOKEN_ABI[settings.NETWORK])

        system_admin = User.objects.get(email=settings.SYSTEM_ADMIN_EMAIL)
        system_credential = UserWalletCredential.objects.get(user=system_admin)
        
        # returns int with balance, without decimals
        token_balance = token_contract.functions.balanceOf(
            system_credential.public_key).call({"from": web3.to_checksum_address(system_credential.public_key)})
        if token_balance <= withdraw_request.amount:
            return Response({
                'data': None,
                'message': "Insufficient token in App, please ask owner"
            },
                status=status.HTTP_400_BAD_REQUEST
            )        
        # fee = round(15 / user_token.token.sell_price, 2)
        user_token = UserToken.objects.get(user=withdraw_request.user, token=token)
        # if user_token.balance < withdraw_request.amount:
        #     return Response(
        #         {
        #             'data': 'null',
        #             'message': 'Insuffient balance'
        #         },
        #         status=status.HTTP_400_BAD_REQUEST
        #     )
        
        amount_to_send = withdraw_request.amount * pow(10, token.decimals)
        # Build transaction
        try:
            transfer_txn = token_contract.functions.transfer(withdraw_addr, int(amount_to_send)).build_transaction({
                'chainId': CONSTANTS.CHAIN_ID[settings.NETWORK],
                'gas': web3.to_hex(CONSTANTS.GAS),
                'gasPrice': web3.to_wei('50', 'gwei'),
                'nonce': web3.eth.get_transaction_count(system_credential.public_key)
            })

            decrypted_private_key = decrypt_private_key(eval(system_credential.private_key), eval(system_credential.encryption_key))
            sign_transfer_txn = web3.eth.account.sign_transaction(transfer_txn, decrypted_private_key)
            txn_hash = web3.eth.send_raw_transaction(sign_transfer_txn.rawTransaction)
        except (Web3Exception, InvalidTransaction, ProviderConnectionError) as e:
            raise e

        withdraw_request.status = 2
        withdraw_request.save()        
        user_token.prev_balance -= withdraw_request.amount        
        user_token.save()
        return Response(
            {
                "data": txn_hash.hex(),
                "message": "Successfully withdrawed to your wallet"
            },
            status=status.HTTP_200_OK
        )        

    def delete(self, request):
        request_id = request.query_params.get('request_id')
        user_withdraw = get_object_or_404(DepositWithdraw, id=request_id)
        user_token = UserToken.objects.get(user=user_withdraw.user, token=user_withdraw.token)
        fee = round(15 / user_token.token.sell_price, 2)
        user_token.balance += user_withdraw.amount + fee
        user_token.save()
        user_withdraw.status = 0
        user_withdraw.save()

        return Response(
            {
                'data': None,
                'message': 'Successfully rejected'
            },
            status=status.HTTP_200_OK
        )


class TransferTokenView(APIView):
    permission_classes = (IsAuthenticated, )
    serializer_class = TransferSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = request.user
            token = Token.objects.get(id=request.data['token_id'])
            user_token = UserToken.objects.get(user=user, token=token)
            amount = float(request.data['amount'])
            if user_token.balance >= amount:
                try:
                    receiver = User.objects.get(
                        email=request.data['receiver_email'])
                except User.DoesNotExist:
                    return Response(
                        {
                            "data": None,
                            "message": "User does not exist"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
                try:
                    receiver_user_token = UserToken.objects.get(
                        user=receiver, token=token)
                    receiver_user_token.balance += amount
                except UserToken.DoesNotExist:
                    UserToken.objects.create(
                        user=receiver, token=token, balance=amount)
                else:
                    receiver_user_token.save()
                    user_token.balance -= amount
                    user_token.save()

                transfer = Transfer.objects.create(
                    _from=user, _to=receiver, token=token, amount=amount,
                )
                return Response(
                    {
                        'data': TransferModelSerializer(transfer).data,
                        'message': 'Transferred token successfully'
                    },
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {
                        'data': None,
                        'message': 'Insufficient balance for sending'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )


class SwapView(APIView):
    permission_classes = (IsAuthenticated, )
    serializer_class = SwapSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = request.user     # Authenticated User

            send_token = Token.objects.get(id=request.data['send_token_id'])
            get_token = Token.objects.get(id=request.data['get_token_id'])
            send_amount = float(request.data['send_amount'])

            if send_token.name == 'USDT' and send_amount < 1000:
                return Response({
                    'data': None,
                    'message': 'Minimum USDT swap amount for sending should be greater than 1000'
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                send_user_token = UserToken.objects.get(
                    user=user, token=send_token)
            except UserToken.DoesNotExist:
                raise ValueError("User does not exist.")

            get_user_token = UserToken.objects.get(
                user=user, token=get_token)            
            if send_amount <= send_user_token.balance:
                send_user_token.balance = send_user_token.balance - \
                    send_amount  # Remove send amount from user wallet
                get_token_balance = send_amount * send_token.sell_price / get_token.buy_price
                get_user_token.balance = get_user_token.balance + \
                    get_token_balance              # Add get amount to user wallet
                get_user_token.save()
                send_user_token.save()

                Swap.objects.create(
                    user=user, send_token=send_token, get_token=get_token, send_amount=request.data[
                        'send_amount'], get_amount=get_token_balance
                )
                if get_token.name == 'IQDT':
                    user.iqdt_payout_amount += get_token_balance
                    user.save()
                return Response(
                    {
                        'data': {},
                        'message': 'Exchanged token successfully'
                    },
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {
                        'data': None,
                        'message': 'Insufficient fund'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )


class TokenPayoutView(APIView):
    permission_classes = (IsAdminUser,)
    serializer_class = SwapTxSerializer

    def get(self, request):
        target_month = request.query_params.get('target_month')
        if target_month:
            start_date = target_month
            end_date = TransactionUtils.last_date_of_month(target_month)
            try:
                token_IQDT = Token.objects.get(name='IQDT')
            except Token.DoesNotExist:
                raise TypeError('No token found')

            try:
                payout_tx = Swap.objects.filter(
                    get_token=token_IQDT, timestamp__range=(str(start_date), str(end_date)))

                grouped_data = {}
                for obj in self.serializer_class(instance=payout_tx, many=True).data:
                    user_key = obj['user']['id']
                    if user_key in grouped_data:
                        grouped_data[user_key]['send_amount'] += obj['send_amount']
                        grouped_data[user_key]['get_amount'] += obj['get_amount']
                    else:
                        grouped_data[user_key] = {
                            'user': obj['user'],
                            'send_amount': obj['send_amount'],
                            'get_amount': obj['get_amount'],
                            'get_token': obj['get_token'],
                            'timestamp': obj['timestamp'],
                            'id':  obj['id']
                        }

                # Convert the grouped data back to a list
                payout_grouped_list = list(grouped_data.values())

            except Swap.DoesNotExist:
                raise TypeError('No swap found')

            return Response(
                {
                    'data': payout_grouped_list,
                    "message": "Successfully retrieved payout"
                },
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {
                    'data': None,
                    "message": "Bad request"
                }, status=status.HTTP_400_BAD_REQUEST)


class DepositTransactionView(APIView):
    permission_classes = (IsAdminUser, )

    def get(self, request):
        from_date = request.query_params.get('from')
        to_date = request.query_params.get('to')
        if from_date and to_date:
            deposit_tx_list = DepositWithdraw.objects.filter(direct=True, timestamp__range=(str(from_date), str(to_date)))
        else:
            deposit_tx_list = DepositWithdraw.objects.filter(direct=True)
        return Response({
            'data': DepositTxSerializer(instance=deposit_tx_list, many=True).data,
            'message': 'Successfully retreived deposit transactions'
        },
            status=status.HTTP_200_OK
        )


class WithdrawTransactionView(APIView):
    permission_classes = (IsAdminUser, )

    def get(self, request):
        from_date = request.query_params.get('from')
        to_date = request.query_params.get('to')
        if from_date and to_date:
            withdraw_tx_list = DepositWithdraw.objects.filter(
                Q(direct=False) & (Q(status=0) | Q(status=2)),timestamp__range=(str(from_date), str(to_date)))
        else:
            withdraw_tx_list = DepositWithdraw.objects.filter(
                Q(direct=False) & (Q(status=0) | Q(status=2)))
        withdraw_request_list = DepositWithdraw.objects.filter(
            direct=False, status=1)
        return Response({
            'request': DepositTxSerializer(instance=withdraw_request_list, many=True).data,
            'result': DepositTxSerializer(instance=withdraw_tx_list, many=True).data,
            'message': 'Successfully retreived withdraw transactions'
        },
            status=status.HTTP_200_OK
        )


class TransferTransactionView(APIView):
    permission_classes = (IsAdminUser, )

    def get(self, request):
        from_date = request.query_params.get('from')
        to_date = request.query_params.get('to')
        if from_date and to_date:
            transfer_tx_list = Transfer.objects.filter(timestamp__range=(str(from_date), str(to_date)))
        else:
            transfer_tx_list = Transfer.objects.all()
        return Response({
            'data': TransferTxSerializer(instance=transfer_tx_list, many=True).data,
            'message': 'Successfully retreived transfer transactions'
        },
            status=status.HTTP_200_OK
        )


class SwapTransactionView(APIView):
    permission_classes = (IsAdminUser, )

    def get(self, request):
        from_date = request.query_params.get('from')
        to_date = request.query_params.get('to')
        if from_date and to_date:
            swap_tx_list = Swap.objects.filter(timestamp__range=(str(from_date), str(to_date)))
        else:
            swap_tx_list = Swap.objects.all()

        return Response(
            {
                'data': SwapTxSerializer(instance=swap_tx_list, many=True).data,
                'message': 'Successfully retreived swao transactions'
            },
            status=status.HTTP_200_OK
        )

class AppTokenBalanceView(APIView):
    permission_classes = (IsAdminUser,)

    def get(self, request):
        system_admin = User.objects.get(email=settings.SYSTEM_ADMIN_EMAIL)
        system_credential = UserWalletCredential.objects.get(user=system_admin)

        usdt_token = Token.objects.get(name='USDT')
        # declaring the token contract
        usdt_token_contract = web3.eth.contract(
            address=web3.to_checksum_address(usdt_token.contract), abi=CONSTANTS.TOKEN_ABI[settings.NETWORK])
        # returns int with balance, without decimals
        usdt_token_balance = usdt_token_contract.functions.balanceOf(
            system_credential.public_key).call({"from": web3.to_checksum_address(system_credential.public_key)})

        usdt_token_balance = usdt_token_balance / pow(10, usdt_token.decimals)
        
        iqdt_token = Token.objects.get(name='IQDT')
        # declaring the token contract
        iqdt_token_contract = web3.eth.contract(
            address=web3.to_checksum_address(iqdt_token.contract), abi=CONSTANTS.TOKEN_ABI[settings.NETWORK])
        # returns int with balance, without decimals
        iqdt_token_balance = iqdt_token_contract.functions.balanceOf(
            system_credential.public_key).call({"from": web3.to_checksum_address(system_credential.public_key)})
        iqdt_token_balance = iqdt_token_balance / pow(10, iqdt_token.decimals)

        sold_sum = Swap.objects.filter(send_token=iqdt_token).aggregate(sum_value=Sum('get_amount'))
        if sold_sum['sum_value'] is None:
            iqdt_sold_amount = 0            
        else:
            iqdt_sold_amount = round(sold_sum['sum_value'], 2)
        
        return Response({
            'data': {
                'usdt': usdt_token_balance,
                'iqdt': iqdt_token_balance,
                'iqdt_sales': iqdt_sold_amount
            },
            'message': 'Successfully retrieved app balances'
        },status=status.HTTP_200_OK)

class TxHistoryView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        user = request.user
        deposit_tx_list = DepositWithdraw.objects.filter(direct=True, user=user)
        withdraw_tx_list = DepositWithdraw.objects.filter(direct=False, user=user)
        transfer_tx_list = Transfer.objects.filter(Q(_from=user) | Q(_to=user))
        swap_tx_list = Swap.objects.filter(user=user)

        return Response({
            'history': {
                'deposit': DepositTxSerializer(instance=deposit_tx_list, many=True).data,
                'withdraw': DepositTxSerializer(instance=withdraw_tx_list, many=True).data,
                'transfer': TransferTxSerializer(instance=transfer_tx_list, many=True).data,
                'swap': SwapTxSerializer(instance=swap_tx_list, many=True).data
            },
            'message': 'Successfully retrieved all transaction histories'
        },status=status.HTTP_200_OK)

class AutoCollectionView(APIView):
    permission_classes = (IsAdminUser, )

    def get(self, request):
        if settings.SYSTEM_ADMIN_EMAIL == request.user.email:
            hardware_addr = request.query_params.get('hardare_addr')
            collect_setting = AutoCollectSetting.objects.first()
            collect_setting.hardware_wallet = hardware_addr
            collect_setting.save()

            return Response({'data': True, 'message': 'Updated hardware wallet successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'data': False, 'message': 'Only system admin can update this.'}, status=status.HTTP_403_FORBIDDEN)

    def put(self, request):        
        collect_setting = AutoCollectSetting.objects.first()
        if collect_setting:
            collect_setting.is_auto = request.data['is_auto']
            collect_setting.save()
        else:
            AutoCollectSetting.objects.create(is_auto=request.data['is_auto'])
        
        return Response({'data': None, 'message': 'Updated setting successfully'}, status=status.HTTP_200_OK)

    def post(self, request):
        min_amount = request.query_params.get('min_amount') # This amount means the balance which will be collected to system wallet.
        usdt_token = Token.objects.get(name='USDT')
        system_admin = User.objects.get(email=settings.SYSTEM_ADMIN_EMAIL)
        user_token_list = UserToken.objects.filter(prev_balance__gt=min_amount, token=usdt_token).exclude(user=system_admin)
        recipient_list = []
        for user_token in user_token_list:
            user_wallet = UserWalletCredential.objects.get(user=user_token.user)
            recipient_list.append({
                'id': user_token.id,
                'address': user_wallet.public_key,
                'private_key': user_wallet.private_key,
                'collect_amount': user_token.prev_balance * pow(10, user_token.token.decimals),
                'encryption_key': user_wallet.encryption_key
            })
        
        system_credential = UserWalletCredential.objects.get(user=system_admin)
        system_wallet_balance_wei = web3.eth.get_balance(system_credential.public_key)
        system_wallet_balance = web3.from_wei(system_wallet_balance_wei, 'ether')
        decrypted_system_private_key = decrypt_private_key(eval(system_credential.private_key), eval(system_credential.encryption_key))
        
        total_eth_amount_to_send = 0.005 * len(recipient_list)

        if system_wallet_balance < total_eth_amount_to_send:
            return Response({'data': None, 'message': 'ETHの残高が不足しています。システム管理者のウォレットにETHを追加してください'}, status=status.HTTP_400_BAD_REQUEST)

        # Create a list to store the signed transactions
        signed_transactions = []
        # Create and sign transactions for each recipient
        for recipient in recipient_list:
            eth_transaction = {
                "from": system_credential.public_key,
                "to": recipient["address"],
                "value": web3.to_wei(0.005, "ether"),  # Convert amount to wei
                "gas": 21000,  # Standard gas limit for a simple transaction
                "gasPrice": web3.eth.gas_price,
                "nonce": web3.eth.get_transaction_count(system_credential.public_key),
            }            
            signed_transaction = web3.eth.account.sign_transaction(eth_transaction, decrypted_system_private_key)
            signed_transactions.append(signed_transaction.rawTransaction)

        # Send all signed transactions in a single batch
        for raw_transaction in signed_transactions:
            tx_hash = web3.eth.send_raw_transaction(raw_transaction)
            print(f"Transaction sent. Transaction Hash: {tx_hash.hex()}")
        
        time.sleep(30)

        for recipient_item in recipient_list:            
            usdt_token_contract = web3.eth.contract(address=web3.to_checksum_address(usdt_token.contract), abi=CONSTANTS.TOKEN_ABI[settings.NETWORK])
            token_transaction = usdt_token_contract.functions.transfer(system_credential.public_key, int(recipient['collect_amount'])).build_transaction({
                'chainId': CONSTANTS.CHAIN_ID[settings.NETWORK],
                'gas': web3.to_hex(CONSTANTS.GAS),
                'gasPrice': web3.to_wei('30', 'gwei'),
                'nonce': web3.eth.get_transaction_count(recipient_item['address'])
            })
            decrypted_private_key = decrypt_private_key(eval(recipient_item['private_key']), eval(recipient_item['encryption_key']))
            signed_token_transaction = web3.eth.account.sign_transaction(token_transaction, decrypted_private_key)
            tx_hash = web3.eth.send_raw_transaction(signed_token_transaction.rawTransaction)
            print(f"Transaction sent. Transaction Hash: {tx_hash.hex()}")     

            current_user_token = UserToken.objects.get(id=recipient_item['id'])
            current_user_token.prev_balance = 0
            current_user_token.save()

        collect_setting = AutoCollectSetting.objects.first()

        token_balance = usdt_token_contract.functions.balanceOf(system_credential.public_key).call({"from": web3.to_checksum_address(system_credential.public_key)})
        
        if token_balance > 1000 * pow(10, usdt_token.decimals):
            hardware_tx = usdt_token_contract.functions.transfer(collect_setting.hardware_wallet, int(token_balance * 0.9)).build_transaction({
                    'chainId': CONSTANTS.CHAIN_ID[settings.NETWORK],
                    'gas': web3.to_hex(CONSTANTS.GAS),
                    'gasPrice': web3.to_wei('30', 'gwei'),
                    'nonce': web3.eth.get_transaction_count(recipient_item['address'])
                })
        
            signed_transaction = web3.eth.account.sign_transaction(hardware_tx, decrypted_system_private_key)

        return Response({
            'data': True,
            'message': 'Successfully collected.'
        }, status=status.HTTP_200_OK)        