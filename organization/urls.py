from django.urls import path

from . import views

app_name = 'organization'

urlpatterns = [
    path('workspace/<uuid:org_id>/', views.workspaceAdmin, name='workspace'),
    path('projects/<uuid:org_id>/', views.projects, name='projects'),
    path('storage/<uuid:org_id>/', views.storage, name='storage'),
]
