
import base64
import hashlib
import json
import logging
import os
import re
from uuid import uuid4

import flask
import jwt
import requests
from flask import current_app, redirect, request, url_for
from flask_dance.consumer.base import (BaseOAuthConsumerBlueprint,
                                       oauth_authorized, oauth_before_login,
                                       oauth_error)
from flask_dance.consumer.requests import OAuth2Session
from flask_login import current_user
from jwt import PyJWKClient
from oauthlib.oauth2 import MissingCodeError
from werkzeug.utils import cached_property
from werkzeug.wrappers import Response

log = logging.getLogger(__name__)



class CryptrOAuth2ConsumerBlueprint(BaseOAuthConsumerBlueprint):
    """
    A subclass of :class:`flask.Blueprint` that sets up OAuth 2 authentication.
    """

    def __init__(
        self,
        name,
        import_name,
        tenant_domain,
        audience,
        client_id=None,
        client_secret=None,
        *,
        client=None,
        auto_refresh_url=None,
        auto_refresh_kwargs=None,
        scope=None,
        state=None,
        static_folder=None,
        static_url_path=None,
        template_folder=None,
        url_prefix=None,
        subdomain=None,
        url_defaults=None,
        root_path=None,
        login_url=None,
        authorized_url=None,
        base_url=None,
        authorization_url=None,
        authorization_url_params=None,
        token_url=None,
        token_url_params=None,
        redirect_url=None,
        redirect_to=None,
        session_class=None,
        storage=None,
        rule_kwargs=None,
        dedicated_server=False,
        default_locale='en',
        production_mode=True,
        jwks_base_url=None,
        **kwargs,
    ):
        """
        Most of the constructor arguments are forwarded either to the
        :class:`flask.Blueprint` constructor or the
        :class:`requests_oauthlib.OAuth2Session` constructor, including
        ``**kwargs`` (which is forwarded to
        :class:`~requests_oauthlib.OAuth2Session`).
        Only the arguments that are relevant to Flask-Dance are documented here.

        Args:
            base_url: The base URL of the OAuth provider.
                If specified, all URLs passed to this instance will be
                resolved relative to this URL.
            authorization_url: The URL specified by the OAuth provider for
                obtaining an
                `authorization grant <https://datatracker.ietf.org/doc/html/rfc6749#section-1.3>`__.
                This can be an fully-qualified URL, or a path that is
                resolved relative to the ``base_url``.
            authorization_url_params (dict): A dict of extra
                key-value pairs to include in the query string of the
                ``authorization_url``, beyond those necessary for a standard
                OAuth 2 authorization grant request.
            token_url: The URL specified by the OAuth provider for
                obtaining an
                `access token <https://datatracker.ietf.org/doc/html/rfc6749#section-1.4>`__.
                This can be an fully-qualified URL, or a path that is
                resolved relative to the ``base_url``.
            token_url_params (dict): A dict of extra
                key-value pairs to include in the query string of the
                ``token_url``, beyond those necessary for a standard
                OAuth 2 access token request.
            login_url: The URL route for the ``login`` view that kicks off
                the OAuth dance. This string will be
                :ref:`formatted <python:formatstrings>`
                with the instance so that attributes can be interpolated.
                Defaults to ``/{bp.name}``, so that the URL is based on the name
                of the blueprint.
            authorized_url: The URL route for the ``authorized`` view that
                completes the OAuth dance. This string will be
                :ref:`formatted <python:formatstrings>`
                with the instance so that attributes can be interpolated.
                Defaults to ``/{bp.name}/authorized``, so that the URL is
                based on the name of the blueprint.
            redirect_url: When the OAuth dance is complete,
                redirect the user to this URL.
            redirect_to: When the OAuth dance is complete,
                redirect the user to the URL obtained by calling
                :func:`~flask.url_for` with this argument. If you do not specify
                either ``redirect_url`` or ``redirect_to``, the user will be
                redirected to the root path (``/``).
            session_class: The class to use for creating a Requests session
                between the consumer (your website) and the provider (e.g.
                Twitter). Defaults to
                :class:`~flask_dance.consumer.requests.OAuth2Session`.
            storage: A token storage class, or an instance of a token storage
                class, to use for this blueprint. Defaults to
                :class:`~flask_dance.consumer.storage.session.SessionStorage`.
            rule_kwargs (dict, optional): Additional arguments that should be passed when adding
                the login and authorized routes. Defaults to ``None``.
        """
        BaseOAuthConsumerBlueprint.__init__(
            self,
            name,
            import_name,
            static_folder=static_folder,
            static_url_path=static_url_path,
            template_folder=template_folder,
            url_prefix=url_prefix,
            subdomain=subdomain,
            url_defaults=url_defaults,
            root_path=root_path,
            login_url=login_url,
            authorized_url=authorized_url,
            storage=storage,
            rule_kwargs=rule_kwargs,
        )

        self.add_url_rule(
            rule="/{bp.name}/logout".format(bp=self),
            endpoint="logout",
            view_func=self.logout,
            **{}
        )
        
        self.add_url_rule(
            rule="/{bp.name}/refresh".format(bp=self),
            endpoint="refresh",
            view_func=self.refresh,
            **{}
        )

        self.tenant_domain = tenant_domain
        self.default_locale = default_locale
        self.audience = audience

        self.base_url = base_url
        self.jwks_base_url = jwks_base_url or self.base_url
        self.session_class = session_class or OAuth2Session

        # passed to OAuth2Session()
        self._client_id = client_id
        self.client = client
        self.auto_refresh_url = auto_refresh_url
        self.auto_refresh_kwargs = auto_refresh_kwargs
        self.scope = scope
        self.state = state
        self.kwargs = kwargs
        self.client_secret = client_secret

        self.magic_link_auth_url = "{base_url}/t/{tenant_domain}/user_locale/transaction-pkce-state/sign_type/new".format(base_url=self.base_url, tenant_domain=self.tenant_domain)

        self.sso_gateway_auth_url = "{base_url}/".format(base_url=self.base_url) if dedicated_server else "{base_url}/t/{tenant_domain}".format(base_url=self.base_url, tenant_domain=self.tenant_domain)

        # used by view functions
        self.authorization_url = self.magic_link_auth_url
        self.authorization_url_params = authorization_url_params or {}
        self.token_url = f"{self.base_url}/api/v1/tenants/tenant-domain/client_id/transaction-pkce-state/oauth/sign_type/client/auth-id/token"
        self.token_url_params = token_url_params or {}
        self.redirect_url = redirect_url
        self.redirect_to = redirect_to

        self.production_mode = production_mode

        self.teardown_app_request(self.teardown_session)

    @property
    def client_id(self):
        return self.session.client_id

    @client_id.setter
    def client_id(self, value):
        self.session.client_id = value
        # due to a bug in requests-oauthlib, we need to set this manually
        self.session._client.client_id = value

    @cached_property
    def session(self):
        """
        This is a session between the consumer (your website) and the provider
        (e.g. Twitter). It is *not* a session between a user of your website
        and your website.
        :return:
        """
        ret = self.session_class(
            client_id=self._client_id,
            client=self.client,
            auto_refresh_url=self.auto_refresh_url,
            auto_refresh_kwargs=self.auto_refresh_kwargs,
            scope=self.scope,
            state=self.state,
            blueprint=self,
            base_url=self.base_url,
            **self.kwargs,
        )

        def token_updater(token):
            self.token = token

        ret.token_updater = token_updater
        return self.session_created(ret)

    def session_created(self, session):
        return session

    def teardown_session(self, exception=None):
        try:
            del self.session
        except KeyError:
            pass


    def build_auth_params(self, **auth_params):
        code_verifier = self.build_code_verifier()
        code_challenge = self.build_code_challenge(code_verifier=code_verifier)
        new_params = dict(code_challenge_method='S256', code_challenge=code_challenge, **auth_params)
        return (code_verifier, code_challenge, new_params)

    def build_code_verifier(self):
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
        code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)
        return code_verifier

    def build_code_challenge(self, code_verifier):
        code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
        code_challenge = code_challenge.replace('=', '')
        return code_challenge

    def base_authorization_url(self):
        print(flask.session)
        return self.sso_gateway_auth_url if (('sso_gateway' in flask.session) and flask.session['sso_gateway']) else self.magic_link_auth_url

    def jwks_url(self, token_domain):
        return f'{self.jwks_base_url}/t/{token_domain}/.well-known/jwks'

    def issuer(self, token_domain):
        return f'{self.base_url}/t/{token_domain}'


    def verification_attributes(self, token_domain):
        issuer = self.issuer(token_domain=token_domain)
        required_claims = ['tnt', 'cid', 'ips', 'sci', 'dbs', 'email', 'jtt', 'scp', 'sub', 'ver']
        return dict(algorithms=['RS256'], issuer=issuer, audience=self.audience, options={'require': required_claims})

    def verify_token(self, token):
        decoded = jwt.decode(token, options={'verify_aud': False, 'verify_signature': False})
        token_domain = decoded['tnt']
        
        jwks_url = self.jwks_url(token_domain=token_domain)
        jwks_client = PyJWKClient(jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        return jwt.decode(token, signing_key.key, **self.verification_attributes(token_domain=token_domain))


    def login(self):
        log.debug("\n---\nlogin\n---")
        self.session.redirect_uri = url_for(".authorized", _external=True)
        code_verifier, code_challenge, new_params = self.build_auth_params(**self.authorization_url_params)
        # print('code_verifier', code_verifier)
        print('code_verifier', code_verifier)
        print('code_challenge', code_challenge)

        user_locale = flask.session["locale"] if 'locale' in flask.session else self.default_locale

        print('authorization_url', self.authorization_url)
        url, state = self.session.authorization_url(
            self.base_authorization_url(), state=self.state, **new_params
        )
        url= url.replace("/transaction-pkce-state/", "/" + state + "/")
        url= url.replace("/user_locale/", "/" + user_locale + "/")
        url= url.replace("state=", "client_state=")
        print(f'\n{url}\n')
        state_key = f"{self.name}_oauth_state"
        flask.session[state_key] = state
        code_verifier_key = f"{self.name}_oauth_code_verifier"
        flask.session[code_verifier_key] = code_verifier
        # log.debug("state = %s", state)
        oauth_before_login.send(self, url=url)
        if 'sso_gateway' in flask.session and flask.session['sso_gateway']:
            log.debug("should use sso")
            url += f'&locale={user_locale}'
            if "idp_ids" in flask.session:
                for idp_id in flask.session['idp_ids']:
                    url += f'&idp_ids[]={idp_id}'
                flask.session.pop("idp_ids")
        else:
            log.debug("should use magic link")
            url = url.replace("/sign_type/", "/" + "signin" + "/")
        log.debug("redirect URL = %s", url)
        log.debug("\n---\n")
        return redirect(url)

    def logout(self):
        if 'refresh_token' in flask.session:
            print(current_user.id)
            refresh_token = flask.session['refresh_token']
            tenant_domain = refresh_token.split('.')[0] if '.' in refresh_token else self.tenant_domain
            logout_url = f'{self.base_url}/api/v1/tenants/{tenant_domain}/{self.client_id}/oauth/token/revoke'
            revoke_token_resp = requests.post(logout_url, json={'token': refresh_token, 'token_type_hint': 'refresh_token'}, verify=self.production_mode)
            revoke_json_resp = revoke_token_resp.json()
            if 'revoked_at' in revoke_json_resp:
                flask.session.clear()
            if 'slo_code' in revoke_json_resp:
                slo_code = revoke_json_resp['slo_code']
                slo_after_revoke_url = f'{self.base_url}/api/v1/tenants/{tenant_domain}/{self.client_id}/oauth/token/slo-after-revoke-token?slo_code={slo_code}&target_url={request.base_url}'
                return redirect(slo_after_revoke_url)
            else:
                return redirect('/')
        else:
            print('user mxin')
            return redirect('/')
   
    def refresh(self):
        if 'cryptr_oauth_token' in flask.session and 'refresh_token' in flask.session['cryptr_oauth_token']:
            refresh_token = flask.session['cryptr_oauth_token']['refresh_token']
            tenant_domain = refresh_token.split('.')[0] if '.' in refresh_token else self.tenant_domain
            refresh_token_url = f'{self.base_url}/api/v1/tenants/{tenant_domain}/{self.client_id}/transaction-pkce-state/oauth/client/token'
            refreshed_token = self.session.refresh_token(refresh_token_url.replace('transaction-pkce-state', str(uuid4())), refresh_token=refresh_token, verify=self.production_mode, nonce=str(uuid4()))
            log.debug("refresh_data \n%s\n", refreshed_token)
            self.token = refreshed_token
            return redirect(request.base_url)
        else:
            return redirect(request.base_url)

    def authorized(self):
        """
        This is the route/function that the user will be redirected to by
        the provider (e.g. Twitter) after the user has logged into the
        provider's website and authorized your app to access their account.
        """
        if self.redirect_url:
            next_url = self.redirect_url
        elif self.redirect_to:
            next_url = url_for(self.redirect_to)
        else:
            next_url = "/"
        log.debug("next_url = %s", next_url)

        # check for error in request args
        error = request.args.get("error")
        if error:
            error_desc = request.args.get("error_description")
            error_uri = request.args.get("error_uri")
            log.warning(
                "OAuth 2 authorization error: %s description: %s uri: %s",
                error,
                error_desc,
                error_uri,
            )
            oauth_error.send(
                self, error=error, error_description=error_desc, error_uri=error_uri
            )
            return redirect(next_url)

        log.debug(flask.session)
        state_key = f"{self.name}_oauth_state"
        code_verifier_key = f"{self.name}_oauth_code_verifier"
        if state_key not in flask.session:
            # can't validate state, so redirect back to login view
            log.info("state not found, redirecting user to login")
            return redirect(url_for(".login"))

        code_verifier = flask.session[code_verifier_key]
        state = flask.session[state_key]
        log.debug("state = %s", state)
        self.session._state = state
        del flask.session[state_key]

        self.session.redirect_uri = url_for(".authorized", _external=True)

        dyn_token_url = self.token_url.replace("transaction-pkce-state", state)
        dyn_token_url = dyn_token_url.replace("tenant-domain", request.args.get('organization_domain') if 'organization_domain' in request.args else self.tenant_domain)
        dyn_token_url = dyn_token_url.replace("client_id", self.client_id)
        dyn_token_url = dyn_token_url.replace("auth-id", request.args["authorization_id"])
        dyn_token_url = dyn_token_url.replace("sign_type", 'sso' if ('sso_gateway' in flask.session and flask.session['sso_gateway']) else 'signin')

        print(f"\ndyn_token_url\n{dyn_token_url}\n")
        tok_url_params = dict(code_verifier=code_verifier, nonce="some-nonce", **self.token_url_params)
        try:
            token = self.session.fetch_token(
                dyn_token_url,
                authorization_response=request.url,
                client_secret=self.client_secret,
                verify=self.production_mode,
                **tok_url_params,
            )
        except MissingCodeError as e:
            e.args = (
                e.args[0],
                "The redirect request did not contain the expected parameters. Instead I got: {}".format(
                    json.dumps(request.args)
                ),
            )
            raise

        

        results = oauth_authorized.send(self, token=token) or []
        set_token = True
        for func, ret in results:
            if isinstance(ret, (Response, current_app.response_class)):
                return ret
            if ret == False:
                set_token = False

        if set_token:
            try:
                print('\nset token\n')
                verified_claims = self.verify_token(token['access_token'])
                log.debug('verify_claims %s', verified_claims)
                for key in ['locale', 'cryptr_oauth_code_challenge', 'cryptr_oauth_code_verifier', 'locale', 'sso_gateway']:
                    if key in flask.session:
                        flask.session.pop(key)
                self.token = token
            except ValueError as error:
                log.warning("OAuth 2 authorization error: %s", str(error))
                oauth_error.send(self, error=error)
        return redirect(next_url)
