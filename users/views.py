from rest_framework.views import APIView, Response, status
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
# from task.models import Task
from django.contrib.auth.hashers import make_password
from django.db import IntegrityError
# from rest_framework.permissions import IsAuthenticated


class RegisterView(APIView):
    # permission_classes = [IsAuthenticated]
    @staticmethod
    def post(request):
        if request.method == 'POST':
            first_name = request.data.get('first_name')
            last_name = request.data.get('last_name')
            username = request.data.get('username')
            email = request.data.get('email')
            password = request.data.get('password')
            password_repeat = request.data.get('password_repeat')

            if password != password_repeat:
                return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)

            hashed_password = make_password(password)
            try:
                user = User.objects.create_user(username=username, email=email, password=hashed_password)
                user.first_name = first_name
                user.last_name = last_name
                user.save()
                return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
            except IntegrityError:
                return Response({'error': 'User with this username or email already exists'},
                                status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({'message': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)

        if user is not None:
            login(request, user)
            return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)

    # class UserTasksView(APIView):
    #     def get(self, request):
    #     if not request.user.is_authenticated:
    #         return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
    #
    #     user_tasks = Task.objects.filter(user=request.user)
    #     return Response({'tasks': user_tasks}, status=status.HTTP_200_OK)
