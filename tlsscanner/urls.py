"""tlsscanner URL Configuration
"""
from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^report/(?P<targethost>[A-Za-z0-9\.]+)/(?P<targetport>[0-9]+)/$', views.do, name='do'),
    url(r'^about/$', views.about, name='about'),
    url(r'^register/$', views.register, name='register'),
    url(r'^login/$', views.user_login, name='user_login'),
    url(r'^submitscan$', views.submitscan, name='submitscan'),
    url(r'^logout/$', views.user_logout, name='user_logout'),
    url(r'^restricted/$', views.restricted, name='user_restricted'),
    
]
