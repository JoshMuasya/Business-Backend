from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

from .serializers import UserSerializer

@api_view(['POST'])
def login(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({"detail": "Email and Password fields cannot be empty"}, status=status.HTTP_403_FORBIDDEN)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"detail": "Not Found."}, status=status.HTTP_404_NOT_FOUND)
    
    if not user.check_password(password):
        return Response({"detail": "Credentials do not match."}, status=status.HTTP_401_UNAUTHORIZED)

    token, created = Token.objects.get_or_create(user=user)
    serializer = UserSerializer(instance=user)
    return Response({"token": token.key, "user": serializer.data})

@api_view(['POST'])
def signup(request):
    email = request.data.get('email')
    username = request.data.get('username')
    password = request.data.get('password')
    confirm_password = request.data.get('confirm_password')

    if not email or not username or not password or not confirm_password:
        return Response({"error": "Fields can't be blank"}, status=status.HTTP_403_FORBIDDEN)

    serializer = UserSerializer(data=request.data)

    if serializer.is_valid():
        
        # Check if email already exists
        if User.objects.filter(email=email).exists():
            return Response({"error": "Email already exists"}, status=status.HTTP_409_CONFLICT)
        
        # Check if username already exists
        if User.objects.filter(username=username).exists():
            return Response({"error": "Username already exists"}, status=status.HTTP_410_GONE)
        
        # Check if passwords match
        if password != confirm_password:
            return Response({"error": "Passwords do not match"}, status=status.HTTP_417_EXPECTATION_FAILED)
        
        # Create new User
        user = serializer.save()
        user.set_password(request.data['password'])
        user.save()

        # Generate Token
        token = Token.objects.create(user=user)

        return Response({"token": token.key, "user": serializer.data})
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def test_token(request):
    return Response("passed for {}".format(request.user.username))