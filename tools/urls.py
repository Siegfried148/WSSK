from django.conf.urls import include, url
from . import views

urlpatterns = [
        url(r'^$', views.tool_list, name='tool_list'),
        url(r'^crypto', views.crypto, name = 'crypto'),
        url(r'^scanner', views.scanner, name = 'scanner'),
        url(r'^passive', views.passive, name = 'passive'),
        url(r'^active', views.active, name ='active'),
        url(r'^network', views.network, name = 'network'),
    ]
