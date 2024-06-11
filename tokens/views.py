from django.db.models import F
from django.shortcuts import get_object_or_404
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status

from .serializer import TokenSerializer, UserTokenSerializer
from .models import Token, UserToken
from user.models import User
from transaction.models import AutoCollectSetting

# Create your views here.


class TokenView(APIView):
    permission_classes = (IsAuthenticated, IsAdminUser)
    serializer_class = TokenSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            token = Token.objects.create(**serializer.validated_data)
            return Response(
                {
                    "data": self.serializer_class(instance=token).data,
                    "message": "Created new token successfully",
                },
                status=status.HTTP_201_CREATED

            )
        else:
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

    def put(self, request):
        token_id = request.query_params.get("token_id")
        token = get_object_or_404(Token, id=token_id)
        serializer = self.serializer_class(
            instance=token, data=request.data, partial=True)

        if serializer.is_valid():
            try:
                token = Token.objects.get(id=token_id)
            except Token.DoesNotExist:
                raise TypeError("Token does not exist")

            token.name = request.data['name']
            token.symbol = request.data['symbol']
            token.contract = request.data['contract']
            token.decimals = request.data['decimals']
            token.sell_price = request.data['sell_price']
            token.buy_price = request.data['buy_price']
            token.icon = request.data['icon']

            token.save()

            return Response(
                {
                    "data": self.serializer_class(instance=token).data,
                    "message": "Updated token successfully"
                },
                status=status.HTTP_200_OK
            )
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        delete_id = request.query_params.get("token_id")
        try:
            delete_token = Token.objects.get(id=delete_id).delete()
        except Token.DoesNotExist:
            raise TypeError("Token does not exist")

        return Response(
            {
                "data": self.serializer_class(instance=delete_token, partial=True).data,
                "message": "Deleted token successfully"
            },
            status=status.HTTP_202_ACCEPTED
        )


class TokenViewForUser(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = TokenSerializer

    def get(self, request):
        token_id = request.query_params.get("token_id")
        if token_id:
            try:
                token = Token.objects.get(id=token_id)
            except Token.DoesNotExist:
                raise TypeError("Token does not exist")

            return Response(
                {
                    "data": self.serializer_class(instance=token).data,
                    "message": "Retrieved one token"
                },
                status=status.HTTP_200_OK
            )
        else:
            app_tokens = Token.objects.all().values()
            return Response(
                {
                    "data": app_tokens,
                    "message": "Retrieved all app tokens"
                },
                status=status.HTTP_200_OK
            )


class GetUserTokenView(APIView):
    permission_classes = (IsAuthenticated, )
    serializer_class = ()

    def get(self, request):
        user = request.user
        user_token_list = UserToken.objects.filter(
            user=user).values('balance', id=F('token__id'), type=F('token__type'), name=F('token__name'), symbol=F('token__symbol'), decimals=F('token__decimals'), contract=F('token__contract'),  sell_price=F('token__sell_price'), buy_price=F('token__buy_price'), icon=F('token__icon'))
        return Response(
            {
                "data": user_token_list,
                "message": "Retrieved user token successfully"
            },
            status=status.HTTP_200_OK
        )

class UserTokenBalanceView(APIView):
    permission_classes = (IsAdminUser, )
    serializer_class = UserTokenSerializer

    def get(self, request):
        system_admin = User.objects.get(email=settings.SYSTEM_ADMIN_EMAIL)
        user_token_list = UserToken.objects.filter(prev_balance__gt=0).exclude(user=system_admin)
        collect_setting = AutoCollectSetting.objects.first()

        return Response(
            {
                "data": self.serializer_class(instance=user_token_list, many=True).data,
                "collect_setting": {
                    "is_auto": collect_setting.is_auto,
                    "hardware_wallet": collect_setting.hardware_wallet
                },
                "message": "Retrieved user token successfully"
            },
            status=status.HTTP_200_OK
        )
