"""Offline OAuth client and upstream security regressions. No provider calls."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import requests
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import RequestValidator, Server, MismatchingStateError, InsecureTransportError
from oauthlib.oauth2.rfc6749.clients import WebApplicationClient

class OAuthCompatibilityTests(unittest.TestCase):
    def test_pkce_authorization_and_mock_token_exchange(self):
        session = OAuth2Session('synthetic-client', redirect_uri='https://client.example.invalid/callback', state='expected-state', pkce='S256')
        url, state = session.authorization_url('https://provider.example.invalid/authorize')
        query = parse_qs(urlsplit(url).query)
        self.assertEqual(query['code_challenge_method'], ['S256'])
        self.assertEqual(query['state'], ['expected-state'])
        self.assertTrue(query['code_challenge'][0])
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps({'access_token': 'synthetic-access-token', 'token_type': 'Bearer'}).encode()
        def offline_send(prepared, **kwargs):
            response.request = prepared
            response.url = prepared.url
            return response
        with patch.object(session, 'send', side_effect=offline_send) as transport:
            token = session.fetch_token('https://provider.example.invalid/token', authorization_response='https://client.example.invalid/callback?code=test-code&state=expected-state', client_secret='synthetic-client-secret')
        self.assertEqual(token['access_token'], 'synthetic-access-token')
        self.assertIn('code_verifier', parse_qs(transport.call_args.args[0].body))
        session.close()

    def test_wrong_callback_state_is_rejected_before_any_network_call(self):
        with OAuth2Session('synthetic-client', state='expected-state') as session:
            with patch.object(session, 'request', side_effect=AssertionError('Network forbidden')) as transport:
                with self.assertRaises(MismatchingStateError):
                    session.fetch_token('https://provider.example.invalid/token', authorization_response='https://client.example.invalid/callback?code=test-code&state=wrong')
                transport.assert_not_called()

    def test_plain_http_authorization_callback_is_rejected(self):
        with self.assertRaises(InsecureTransportError):
            WebApplicationClient('synthetic-client').parse_request_uri_response('http://client.example.invalid/callback?code=test&state=test', state='test')

    def test_revocation_callback_never_returns_jsonp(self):
        class Validator(RequestValidator):
            def authenticate_client(self, request, *args, **kwargs):
                request.client = SimpleNamespace(client_id='synthetic-client')
                return True
            def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
                self.revoked = token
        validator = Validator()
        server = Server(validator)
        headers, body, status = server.create_revocation_response('https://provider.example.invalid/revoke', body='token=synthetic-token&callback=evil')
        self.assertEqual(status, 200)
        self.assertEqual(validator.revoked, 'synthetic-token')
        self.assertEqual(body, '')
        self.assertNotIn('javascript', headers.get('Content-Type', ''))
        headers, body, status = server.create_revocation_response('https://provider.example.invalid/revoke?callback=evil', body='token=synthetic-token')
        self.assertEqual(status, 400)
        self.assertEqual(headers['Content-Type'], 'application/json')
        self.assertEqual(json.loads(body)['error'], 'invalid_request')

    def test_unknown_grant_is_rejected_before_client_authentication(self):
        validator = RequestValidator()
        with patch.object(validator, 'authenticate_client', side_effect=AssertionError('Unsupported grant reached client auth')) as authenticate:
            headers, body, status = Server(validator).create_token_response('https://provider.example.invalid/token', body='grant_type=not-a-real-grant')
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)['error'], 'unsupported_grant_type')
        authenticate.assert_not_called()

    def test_existing_google_oauth_client_still_builds_pkce_request_offline(self):
        from google_auth_oauthlib.flow import Flow
        flow = Flow.from_client_config({'web': {'client_id': 'synthetic-client', 'client_secret': 'synthetic-secret', 'auth_uri': 'https://provider.example.invalid/auth', 'token_uri': 'https://provider.example.invalid/token', 'redirect_uris': ['https://client.example.invalid/callback']}}, scopes=['test-scope'], redirect_uri='https://client.example.invalid/callback', autogenerate_code_verifier=True)
        url, state = flow.authorization_url(state='synthetic-state')
        self.assertEqual(parse_qs(urlsplit(url).query)['code_challenge_method'], ['S256'])
        self.assertEqual(state, 'synthetic-state')
        flow.oauth2session.close()
