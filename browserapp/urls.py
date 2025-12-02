from django.contrib import admin
from django.urls import path, include
from .views import *

urlpatterns = [
path('', home, name='home'),
    path('login/',  google_login, name='google_login'),
    path('oauth2callback',  oauth2callback, name='oauth2callback'),
    path('success/',  gmail_success, name='gmail_success'),
    path('logout/', gmail_logout, name='gmail_logout'),
    path('gmail_auth/', gmail_auth, name='gmail_auth'),
    path("get_gmail /", get_gmail, name="get_gmail"),
    path('run_main/', run_main, name='run_main'),
    path('apply_job/', apply_job, name='apply_job'),
    path("send_job_infos/", send_job_infos, name="send_job_infos"),

]
