from django.urls import path

from . import views

app_name = 'authentication'

urlpatterns = [
    path('', views.landing, name='landing'),
    path('login/', views.login_user, name='login'),
    path('register/', views.register, name='register'),
    path('forgotpassword/', views.forgotpassword, name='forgotpassword'),
    path('changepassword/', views.changepassword, name='changepassword'),
    path('dataseparationact/', views.dataseparationact, name='dataseparationact'),
    path('workspace/', views.workspace, name='workspace'),
    path('workspace_admin/', views.workspaceAdmin, name='workspaceAdmin'),
    path("logout/", views.logout_user, name="logout"),
]
