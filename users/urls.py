from django.urls import path
from .views import RegisterView, LoginView, LogoutView  # UserTasksView


urlpatterns = [
    path('register', RegisterView.as_view(), name='register'),
    path('login', LoginView.as_view(), name='login'),
    path('logout', LogoutView.as_view(), name='logout'),
    # path('tasks', UserTasksView.as_view(), name='user_tasks'),
]