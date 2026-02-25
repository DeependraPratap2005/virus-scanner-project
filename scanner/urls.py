from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('upload/', views.upload_file, name='upload'),
    path('refresh/<int:file_id>/', views.refresh_status, name='refresh'),
    path('report/<int:file_id>/', views.download_report, name='report'),
]