from django.conf.urls import url
from . import views

app_name = 'drf_saml2_auth'

urlpatterns = [
    url(r'^acs/$', views.acs, name="acs"),
]
