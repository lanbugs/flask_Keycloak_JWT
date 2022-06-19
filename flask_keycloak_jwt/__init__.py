#!/usr/bin/env python3

#
# Keycloak JWT Authentication module for Flask
#
# Version 1.0
# Written by Maximilian Thoma 2022
# Visit https://lanbugs.de
#
#
# Required packages:
# - authlib
# - flask
#
# Usage:
# app.py
# ------
# from flask import Flask
# from flask_keycloak_jwt import KeycloakJWT
#
# app = Flask(__name__)
# auth = KeycloakJWT(app)
#
# app.config.update(
#     {
#         "CLIENT_ID": "api_app",
#         "CLIENT_SECRET": "supersecret key",
#         "INTROSPECT_URL": "http://auth.lab.local/auth/realms/testapp/protocol/openid-connect/token/introspect"
#     }
# )
#
# @app.route("/api")
# @auth.require_token
# @auth.check_resource_access("api_app", "view_hello")
# def hello_api():
#     return {"say": "hello"}
#

from functools import wraps
from authlib.integrations.requests_client import OAuth2Session
import json
from flask import request, current_app


class KeykloakJWT(object):

    def __init__(self, app=None):
        self.token = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.config.setdefault('INTROSPECT_URL', None)
        app.config.setdefault('CLIENT_ID', None)
        app.config.setdefault('CLIENT_SECRET', None)

    def require_token(self, view_func):
        """
        Use this to decorate view functions that require a user to be logged in.
        """
        @wraps(view_func)
        def decorated(*args, **kwargs):
            token = None
            if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Bearer '):
                token = request.headers['Authorization'].split(None, 1)[1].strip()
            if 'access_token' in request.form:
                token = request.form['access_token']
            elif 'access_token' in request.args:
                token = request.args['access_token']

            oauth = OAuth2Session(client_id=current_app.config['CLIENT_ID'], client_secret=current_app.config['CLIENT_SECRET'])
            result = oauth.introspect_token(url=current_app.config['INTROSPECT_URL'], token=token)
            content = json.loads(result.content.decode())

            if content['active'] is True:
                self.token = content
                return view_func(*args, **kwargs)
            else:
                response_body = {'error': 'token invalid'}
                response_body = json.dumps(response_body)
                return response_body, 401, {'WWW-Authenticate': 'Bearer'}
        return decorated

    def check_resource_access(self, client, role):
        """
        With this decorator you can check if role is in resource access in the JWT token
        """
        def wrapper(view_func):
            @wraps(view_func)
            def decorated(*args, **kwargs):
                if "resource_access" not in self.token.keys():
                    response_body = {'error': 'no resource_access profiles in token'}
                    response_body = json.dumps(response_body)
                    return response_body, 401, {'WWW-Authenticate': 'Bearer'}

                if client in self.token['resource_access'].keys():
                    if role in self.token['resource_access'][client]['roles']:
                        return view_func(*args, **kwargs)
                    else:
                        response_body = {'error': 'role not in resource_access'}
                        response_body = json.dumps(response_body)
                        return response_body, 401, {'WWW-Authenticate': 'Bearer'}
                else:
                    response_body = {'error': 'client not in resource_access'}
                    response_body = json.dumps(response_body)
                    return response_body, 401, {'WWW-Authenticate': 'Bearer'}

            return decorated
        return wrapper

    def check_realm_access(self, role):
        """
        With this decorator you can check if role is in realm access in the JWT token
        """
        def wrapper(view_func):
            @wraps(view_func)
            def decorated(*args, **kwargs):
                    if "realm_access" not in self.token.keys():
                        response_body = {'error': 'no realm_access roles in token'}
                        response_body = json.dumps(response_body)
                        return response_body, 401, {'WWW-Authenticate': 'Bearer'}

                    if "roles" in self.token['realm_access']:
                        if role in self.token['realm_access']['roles']:
                            return view_func(*args, **kwargs)
                        else:
                            response_body = {'error': 'role not in realm_access'}
                            response_body = json.dumps(response_body)
                            return response_body, 401, {'WWW-Authenticate': 'Bearer'}
                    else:
                        response_body = {'error': 'no roles present in realm_access'}
                        response_body = json.dumps(response_body)
                        return response_body, 401, {'WWW-Authenticate': 'Bearer'}

            return decorated
        return wrapper
