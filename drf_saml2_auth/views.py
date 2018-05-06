#!/usr/bin/env python
# -*- coding:utf-8 -*-


from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

from django import get_version
from pkg_resources import parse_version
from django.conf import settings
from django.contrib.auth.models import (User, Group)
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.template import TemplateDoesNotExist
from django.http import (HttpResponse, HttpResponseRedirect)
from django.utils.http import is_safe_url

try:
    import urllib2 as _urllib
except:
    import urllib.request as _urllib
    import urllib.error
    import urllib.parse

if parse_version(get_version()) >= parse_version('1.7'):
    from django.utils.module_loading import import_string
else:
    from django.utils.module_loading import import_by_path as import_string


def get_current_domain(r):
    if 'ASSERTION_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['ASSERTION_URL']
    return '{scheme}://{host}'.format(
        scheme='https' if r.is_secure() else 'http',
        host=r.get_host(),
    )


def get_reverse(objs):
    '''In order to support different django version, I have to do this '''
    if parse_version(get_version()) >= parse_version('2.0'):
        from django.urls import reverse
    else:
        from django.core.urlresolvers import reverse
    if objs.__class__.__name__ not in ['list', 'tuple']:
        objs = [objs]

    for obj in objs:
        try:
            return reverse(obj)
        except:
            pass


def _get_saml_client(domain):
    acs_url = domain + get_reverse([acs, 'acs', 'django_saml2_auth:acs'])

    saml_settings = {
        'metadata': {
            'remote': [
                {
                    "url": settings.SAML2_AUTH['METADATA_AUTO_CONF_URL'],
                },
            ],
        },
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST)
                    ],
                },
                'allow_unsolicited': True,
                'authn_requests_signed': False,
                'logout_requests_signed': True,
                'want_assertions_signed': True,
                'want_response_signed': False,
            },
        },
    }

    if 'ENTITY_ID' in settings.SAML2_AUTH:
        saml_settings['entityid'] = settings.SAML2_AUTH['ENTITY_ID']

    if 'NAME_ID_FORMAT' in settings.SAML2_AUTH:
        saml_settings['service']['sp']['name_id_format'] = settings.SAML2_AUTH['NAME_ID_FORMAT']

    spConfig = Saml2Config()
    spConfig.load(saml_settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    return saml_client


def _create_new_user(username, email, first_name, last_name, user_saml_groups=set()):
    user = User.objects.create_user(username, email)
    user.first_name = first_name
    user.last_name = last_name

    user_group_map = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('USER_GROUPS_MAP', {})

    for group in user_group_map:
        django_group = Group.objects.get(name=group)
        allowed_saml_groups = user_group_map[group] or set()

        if len(user_saml_groups & allowed_saml_groups) > 0:
            user.groups.add(django_group)

    user.save()
    return user

def _update_existing_user(user, username, email, first_name, last_name, user_saml_groups=set()):
    # update user fields
    user.first_name = first_name
    user.last_name = last_name
    user.email = email

    user_group_map = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('USER_GROUPS_MAP', {})

    for group in user_group_map:
        django_group = Group.objects.get(name=group)
        allowed_saml_groups = user_group_map[group] or set()
        user_allowed = len(user_saml_groups & allowed_saml_groups) > 0

        if django_group in user.groups:
            if not user_allowed:
                user.groups.remove(django_group)
        else:
            if user_allowed:
                user.groups.add(django_group)

    user.save()
    return user

def _create_user_token(user, user_saml_identity=None):
    token_cls = type(target_user.auth_token)
    try:
        # delete the current token, if one exists 
        token_cls.objects.get(user=target_user).delete()
    except token_cls.DoesNotExist:
        pass

    token = token_cls.objects.create(user=target_user)

    return token.key
    
@csrf_exempt
def acs(r):
    saml_client = _get_saml_client(get_current_domain(r))
    resp = r.POST.get('SAMLResponse', None)
    next_url = r.session.get('login_next_url', settings.SAML2_AUTH.get('DEFAULT_NEXT_URL', get_reverse('admin:index')))

    if not resp:
        return HttpResponse('Unauthorized', status=401)

    authn_response = saml_client.parse_authn_request_response(
        resp, entity.BINDING_HTTP_POST)
    if authn_response is None:
        return HttpResponse('Unauthorized', status=401)

    user_identity = authn_response.get_identity()
    if user_identity is None:
        return HttpResponse('Unauthorized', status=401)

    user_email = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('email', 'Email')][0]
    user_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('username', 'UserName')][0]
    user_first_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('first_name', 'FirstName')][0]
    user_last_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('last_name', 'LastName')][0]
    groups = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('member_of', 'memberOf')]

    target_user = None
    is_new_user = False

    try:
        target_user = User.objects.get(username=user_name)
        target_user = _update_existing_user(target_user, user_name, user_email, user_first_name, user_last_name, groups)
        if settings.SAML2_AUTH.get('TRIGGER', {}).get('BEFORE_LOGIN', None):
            import_string(settings.SAML2_AUTH['TRIGGER']['BEFORE_LOGIN'])(target_user, user_identity)
    except User.DoesNotExist:
        target_user = _create_new_user(user_name, user_email, user_first_name, user_last_name, groups)
        if settings.SAML2_AUTH.get('TRIGGER', {}).get('CREATE_USER', None):
            import_string(settings.SAML2_AUTH['TRIGGER']['CREATE_USER'])(target_user, user_identity)
        is_new_user = True

    r.session.flush()

    redirect = HttpResponseRedirect(next_url)

    if settings.SAML2_AUTH.get('CREATE_TOKEN_COOKIE', False):
        token_key = _create_user_token(target_user)
        token_cookie_name = settings.SAML2_AUTH.get('TOKEN_COOKIE_NAME', 'token')

        redirect.set_cookie(token_cookie_name, token_key, secure=True)

    return redirect


def signin(r):
    try:
        import urlparse as _urlparse
        from urllib import unquote
    except:
        import urllib.parse as _urlparse
        from urllib.parse import unquote
    next_url = r.GET.get('next', settings.SAML2_AUTH.get('DEFAULT_NEXT_URL'))

    try:
        if 'next=' in unquote(next_url):
            next_url = _urlparse.parse_qs(_urlparse.urlparse(unquote(next_url)).query)['next'][0]
    except:
        next_url = r.GET.get('next', settings.SAML2_AUTH.get('DEFAULT_NEXT_URL'))

    if not next_url:
        return HttpResponse('Unauthorized', status=401)

    if not is_safe_url(next_url, allowed_hosts=settings.ALLOWED_HOSTS):
        return HttpResponse('Unauthorized', status=401)

    r.session['login_next_url'] = next_url

    saml_client = _get_saml_client(get_current_domain(r))
    _, info = saml_client.prepare_for_authenticate()

    redirect_url = None

    for key, value in info['headers']:
        if key == 'Location':
            redirect_url = value
            break

    return HttpResponseRedirect(redirect_url)


def signout(r):
    logout(r)
    return HttpResponse('Unauthorized', status=200)
