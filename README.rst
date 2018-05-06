=====================================
DRF SAML2 Authentication
=====================================

:Author: Peter Battaglia

Based off of the django-saml2-auth project, this project aims to provide simple
way to integrate SAML2 Authentication into your Django app. Specifically, this
project doesn't assume you are using Django to serve the front-end of your app,
allowing your SPA to seemlessly integrate with your SSO provider.

Any SAML2 based SSO(Single-Sign-On) identity provider with dynamic metadata
configuration is supported by this Django plugin, for example Okta or OneLogin.


Dependencies
============

This plugin is compatible and has been tested with with Django 1.10.
The `pysaml2` Python module is required.



Install
=======

You can install this plugin via `pip`:

.. code-block:: bash

    # pip install drf_saml2_auth

or from source:

.. code-block:: bash

    # git clone https://github.com/petersbattaglia/drf-saml2-auth
    # cd drf-saml2-auth
    # python setup.py install

xmlsec is also required by pysaml2:

.. code-block:: bash

    # yum install xmlsec1
    // or
    # apt-get install xmlsec1


What does this plugin do?
=========================

This plugin provides an API endpoint for your DRF app that your existing SPA
can navigate to to begin an authenitcation flow with a SAML2 SSO authentication service.
Once the user is logged in and redirected back, the plugin will update/create the user in
the django user model, redirect to the page of the SPAs choosing, while delivering a secure
cookie to the SPA to use for future requests.



How to use?
===========

#. Import the views module in your root urls.py

    .. code-block:: python

        import drf_saml2_auth.views

#. Override the default login page in the root urls.py file, by adding these
   lines **BEFORE** any `urlpatterns`:

    .. code-block:: python

        # These are the SAML2 related URLs. You can change "^saml2_auth/" regex to
        # any path you want, like "^sso_auth/", "^sso_login/", etc. (required)
        url(r'^saml2_auth/', include('drf_saml2_auth.urls')),

        # The following line will replace the default user login with SAML2 (optional)
        # If you want to specific the after-login-redirect-URL, use parameter "?next=/the/path/you/want"
        # with this view.
        url(r'^accounts/login/$', drf_saml2_auth.views.signin),

        # The following line will replace the admin login with SAML2 (optional)
        # If you want to specific the after-login-redirect-URL, use parameter "?next=/the/path/you/want"
        # with this view.
        url(r'^admin/login/$', drf_saml2_auth.views.signin),

#. Add 'drf_saml2_auth' to INSTALLED_APPS

    .. code-block:: python

        INSTALLED_APPS = [
            '...',
            'drf_saml2_auth',
        ]

#. In settings.py, add the SAML2 related configuration DOCS IN PROGRESS!!.

    Please note, the only required setting is **METADATA_AUTO_CONF_URL**.
    The following block shows all required and optional configuration settings
    and their default values.

    .. code-block:: python

        SAML2_AUTH = {
            # Required setting
            'METADATA_AUTO_CONF_URL': '[The auto(dynamic) metadata configuration URL of SAML2]',

            # Optional settings below
            'DEFAULT_NEXT_URL': '/admin',  # Custom target redirect URL after the user get logged in. Default to /admin if not set. This setting will be overwritten if you have parameter ?next= specificed in the login URL.
            'NEW_USER_PROFILE': {
                'USER_GROUPS': [],  # The default group name when a new user logs in
                'ACTIVE_STATUS': True,  # The default active status for new users
                'STAFF_STATUS': True,  # The staff status for new users
                'SUPERUSER_STATUS': False,  # The superuser status for new users
            },
            'ATTRIBUTES_MAP': {  # Change Email/UserName/FirstName/LastName to corresponding SAML2 userprofile attributes.
                'email': 'Email',
                'username': 'UserName',
                'first_name': 'FirstName',
                'last_name': 'LastName',
            },
            'TRIGGER': {
                'CREATE_USER': 'path.to.your.new.user.hook.method',
                'BEFORE_LOGIN': 'path.to.your.login.hook.method',
            },
            'ASSERTION_URL': 'https://mysite.com', # Custom URL to validate incoming SAML requests against
            'ENTITY_ID': 'https://mysite.com/saml2_auth/acs/', # Populates the Issuer element in authn request
            'NAME_ID_FORMAT': FormatString, # Sets the Format property of authn NameIDPolicy element
        }

#. In your SAML2 SSO identity provider, set the Single-sign-on URL and Audience
   URI(SP Entity ID) to http://your-domain/saml2_auth/acs/


Explanation
-----------

**METADATA_AUTO_CONF_URL** Auto SAML2 metadata configuration URL

**NEW_USER_PROFILE** Default settings for newly created users

**ATTRIBUTES_MAP** Mapping of Django user attributes to SAML2 user attributes

**TRIGGER** Hooks to trigger additional actions during user login and creation
flows. These TRIGGER hooks are strings containing a `dotted module name <https://docs.python.org/3/tutorial/modules.html#packages>`_
which point to a method to be called. The referenced method should accept a
single argument which is a dictionary of attributes and values sent by the
identity provider, representing the user's identity.

**TRIGGER.CREATE_USER** A method to be called upon new user creation. This
method will be called before the new user is logged in and after the user's
record is created. This method should accept ONE parameter of user dict.

**TRIGGER.BEFORE_LOGIN** A method to be called when an existing user logs in.
This method will be called before the user is logged in and after user
attributes are returned by the SAML2 identity provider. This method should accept ONE parameter of user dict.

**ASSERTION_URL** A URL to validate incoming SAML responses against. By default,
django-saml2-auth will validate the SAML response's Service Provider address
against the actual HTTP request's host and scheme. If this value is set, it
will validate against ASSERTION_URL instead - perfect for when django running
behind a reverse proxy.

**ENTITY_ID** The optional entity ID string to be passed in the 'Issuer' element of authn request, if required by the IDP.

**NAME_ID_FORMAT** Set to the string 'None', to exclude sending the 'Format' property of the 'NameIDPolicy' element in authn requests.
Default value if not specified is 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'.
