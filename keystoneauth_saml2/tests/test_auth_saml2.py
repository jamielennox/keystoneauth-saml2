#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import uuid

from keystoneauth1 import exceptions
from lxml import etree
from six.moves import urllib

from keystoneauth_saml2.tests import base
from keystoneauth_saml2.tests import client_fixtures
from keystoneauth_saml2.tests import saml2_fixtures
from keystoneauth_saml2.v3 import saml2

ROOTDIR = os.path.dirname(os.path.abspath(__file__))
XMLDIR = os.path.join(ROOTDIR, 'examples', 'xml/')


def make_oneline(s):
    return etree.tostring(etree.XML(s)).replace(b'\n', b'')


def _load_xml(filename):
    with open(XMLDIR + filename, 'rb') as f:
        return make_oneline(f.read())


class AuthenticateviaSAML2Tests(base.TestCase):

    GROUP = 'auth'
    TEST_TOKEN = uuid.uuid4().hex

    def setUp(self):
        super(AuthenticateviaSAML2Tests, self).setUp()

        self.ECP_SP_EMPTY_REQUEST_HEADERS = {
            'Accept': 'text/html; application/vnd.paos+xml',
            'PAOS': ('ver="urn:liberty:paos:2003-08";'
                     '"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"')
        }

        self.ECP_SP_SAML2_REQUEST_HEADERS = {
            'Content-Type': 'application/vnd.paos+xml'
        }

        self.ECP_SAML2_NAMESPACES = {
            'ecp': 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp',
            'S': 'http://schemas.xmlsoap.org/soap/envelope/',
            'paos': 'urn:liberty:paos:2003-08'
        }
        self.ECP_RELAY_STATE = '//ecp:RelayState'
        self.ECP_SERVICE_PROVIDER_CONSUMER_URL = ('/S:Envelope/S:Header/paos:'
                                                  'Request/'
                                                  '@responseConsumerURL')
        self.ECP_IDP_CONSUMER_URL = ('/S:Envelope/S:Header/ecp:Response/'
                                     '@AssertionConsumerServiceURL')
        self.IDENTITY_PROVIDER = 'testidp'
        self.IDENTITY_PROVIDER_URL = 'http://local.url'
        self.PROTOCOL = 'saml2'
        self.FEDERATION_AUTH_URL = '%s/%s' % (
            self.TEST_URL,
            'OS-FEDERATION/identity_providers/testidp/protocols/saml2/auth')
        self.SHIB_CONSUMER_URL = ('https://openstack4.local/'
                                  'Shibboleth.sso/SAML2/ECP')

        self.saml2plugin = saml2.Saml2Token(
            self.TEST_URL,
            self.IDENTITY_PROVIDER, self.IDENTITY_PROVIDER_URL,
            self.TEST_USER, self.TEST_TOKEN, self.PROTOCOL)

    def test_initial_sp_call(self):
        """Test initial call, expect SOAP message."""
        self.requests.register_uri(
            'GET',
            self.FEDERATION_AUTH_URL,
            content=make_oneline(saml2_fixtures.SP_SOAP_RESPONSE))
        a = self.saml2plugin._send_service_provider_request(self.session)

        self.assertFalse(a)

        fixture_soap_response = make_oneline(
            saml2_fixtures.SP_SOAP_RESPONSE)

        sp_soap_response = make_oneline(
            etree.tostring(self.saml2plugin.saml2_authn_request))

        error_msg = "Expected %s instead of %s" % (fixture_soap_response,
                                                   sp_soap_response)

        self.assertEqual(fixture_soap_response, sp_soap_response, error_msg)

        self.assertEqual(
            self.saml2plugin.sp_response_consumer_url, self.SHIB_CONSUMER_URL,
            "Expected consumer_url set to %s instead of %s" % (
                self.SHIB_CONSUMER_URL,
                str(self.saml2plugin.sp_response_consumer_url)))

    def test_initial_sp_call_when_saml_authenticated(self):
        self.requests.register_uri(
            'GET',
            self.FEDERATION_AUTH_URL,
            json=saml2_fixtures.UNSCOPED_TOKEN,
            headers={'X-Subject-Token': saml2_fixtures.UNSCOPED_TOKEN_HEADER})

        a = self.saml2plugin._send_service_provider_request(self.session)
        self.assertTrue(a)
        self.assertEqual(
            saml2_fixtures.UNSCOPED_TOKEN['token'],
            self.saml2plugin.authenticated_response.json()['token'])
        self.assertEqual(
            saml2_fixtures.UNSCOPED_TOKEN_HEADER,
            self.saml2plugin.authenticated_response.headers['X-Subject-Token'])

    def test_get_unscoped_token_when_authenticated(self):
        self.requests.register_uri(
            'GET',
            self.FEDERATION_AUTH_URL,
            json=saml2_fixtures.UNSCOPED_TOKEN,
            headers={'X-Subject-Token': saml2_fixtures.UNSCOPED_TOKEN_HEADER,
                     'Content-Type': 'application/json'})

        token = self.saml2plugin.get_auth_ref(self.session)

        self.assertEqual(saml2_fixtures.UNSCOPED_TOKEN_HEADER,
                         token.auth_token)

    def test_initial_sp_call_invalid_response(self):
        """Send initial SP HTTP request and receive wrong server response."""
        self.requests.register_uri('GET',
                                   self.FEDERATION_AUTH_URL,
                                   text='NON XML RESPONSE')

        self.assertRaises(
            exceptions.AuthorizationFailure,
            self.saml2plugin._send_service_provider_request,
            self.session)

    def test_send_authn_req_to_idp(self):
        self.requests.register_uri('POST',
                                   self.IDENTITY_PROVIDER_URL,
                                   content=saml2_fixtures.SAML2_ASSERTION)

        self.saml2plugin.sp_response_consumer_url = self.SHIB_CONSUMER_URL
        self.saml2plugin.saml2_authn_request = etree.XML(
            saml2_fixtures.SP_SOAP_RESPONSE)
        self.saml2plugin._send_idp_saml2_authn_request(self.session)

        idp_response = make_oneline(etree.tostring(
            self.saml2plugin.saml2_idp_authn_response))

        saml2_assertion_oneline = make_oneline(
            saml2_fixtures.SAML2_ASSERTION)
        error = "Expected %s instead of %s" % (saml2_fixtures.SAML2_ASSERTION,
                                               idp_response)
        self.assertEqual(idp_response, saml2_assertion_oneline, error)

    def test_fail_basicauth_idp_authentication(self):
        self.requests.register_uri('POST',
                                   self.IDENTITY_PROVIDER_URL,
                                   status_code=401)

        self.saml2plugin.sp_response_consumer_url = self.SHIB_CONSUMER_URL
        self.saml2plugin.saml2_authn_request = etree.XML(
            saml2_fixtures.SP_SOAP_RESPONSE)
        self.assertRaises(
            exceptions.Unauthorized,
            self.saml2plugin._send_idp_saml2_authn_request,
            self.session)

    def test_mising_username_password_in_plugin(self):
        self.assertRaises(TypeError,
                          saml2.Saml2Token,
                          self.TEST_URL, self.IDENTITY_PROVIDER,
                          self.IDENTITY_PROVIDER_URL)

    def test_send_authn_response_to_sp(self):
        self.requests.register_uri(
            'POST',
            self.SHIB_CONSUMER_URL,
            json=saml2_fixtures.UNSCOPED_TOKEN,
            headers={'X-Subject-Token': saml2_fixtures.UNSCOPED_TOKEN_HEADER})

        self.saml2plugin.relay_state = etree.XML(
            saml2_fixtures.SP_SOAP_RESPONSE).xpath(
            self.ECP_RELAY_STATE, namespaces=self.ECP_SAML2_NAMESPACES)[0]

        self.saml2plugin.saml2_idp_authn_response = etree.XML(
            saml2_fixtures.SAML2_ASSERTION)

        self.saml2plugin.idp_response_consumer_url = self.SHIB_CONSUMER_URL
        self.saml2plugin._send_service_provider_saml2_authn_response(
            self.session)
        token_json = self.saml2plugin.authenticated_response.json()['token']
        token = self.saml2plugin.authenticated_response.headers[
            'X-Subject-Token']
        self.assertEqual(saml2_fixtures.UNSCOPED_TOKEN['token'],
                         token_json)

        self.assertEqual(saml2_fixtures.UNSCOPED_TOKEN_HEADER,
                         token)

    def test_consumer_url_mismatch_success(self):
        self.saml2plugin._check_consumer_urls(
            self.session, self.SHIB_CONSUMER_URL,
            self.SHIB_CONSUMER_URL)

    def test_consumer_url_mismatch(self):
        self.requests.register_uri('POST', self.SHIB_CONSUMER_URL)
        invalid_consumer_url = uuid.uuid4().hex
        self.assertRaises(
            exceptions.AuthorizationFailure,
            self.saml2plugin._check_consumer_urls,
            self.session, self.SHIB_CONSUMER_URL,
            invalid_consumer_url)

    def test_custom_302_redirection(self):
        self.requests.register_uri(
            'POST',
            self.SHIB_CONSUMER_URL,
            text='BODY',
            headers={'location': self.FEDERATION_AUTH_URL},
            status_code=302)

        self.requests.register_uri(
            'GET',
            self.FEDERATION_AUTH_URL,
            json=saml2_fixtures.UNSCOPED_TOKEN,
            headers={'X-Subject-Token': saml2_fixtures.UNSCOPED_TOKEN_HEADER})

        self.session.redirect = False
        response = self.session.post(
            self.SHIB_CONSUMER_URL, data='CLIENT BODY')
        self.assertEqual(302, response.status_code)
        self.assertEqual(self.FEDERATION_AUTH_URL,
                         response.headers['location'])

        response = self.saml2plugin._handle_http_ecp_redirect(
            self.session, response, 'GET')

        self.assertEqual(self.FEDERATION_AUTH_URL, response.request.url)
        self.assertEqual('GET', response.request.method)

    def test_custom_303_redirection(self):
        self.requests.register_uri(
            'POST',
            self.SHIB_CONSUMER_URL,
            text='BODY',
            headers={'location': self.FEDERATION_AUTH_URL},
            status_code=303)

        self.requests.register_uri(
            'GET',
            self.FEDERATION_AUTH_URL,
            json=saml2_fixtures.UNSCOPED_TOKEN,
            headers={'X-Subject-Token': saml2_fixtures.UNSCOPED_TOKEN_HEADER})

        self.session.redirect = False
        response = self.session.post(
            self.SHIB_CONSUMER_URL, data='CLIENT BODY')
        self.assertEqual(303, response.status_code)
        self.assertEqual(self.FEDERATION_AUTH_URL,
                         response.headers['location'])

        response = self.saml2plugin._handle_http_ecp_redirect(
            self.session, response, 'GET')

        self.assertEqual(self.FEDERATION_AUTH_URL, response.request.url)
        self.assertEqual('GET', response.request.method)

    def test_end_to_end_workflow(self):
        self.requests.register_uri(
            'GET',
            self.FEDERATION_AUTH_URL,
            content=make_oneline(saml2_fixtures.SP_SOAP_RESPONSE))

        self.requests.register_uri('POST',
                                   self.IDENTITY_PROVIDER_URL,
                                   content=saml2_fixtures.SAML2_ASSERTION)

        self.requests.register_uri(
            'POST',
            self.SHIB_CONSUMER_URL,
            json=saml2_fixtures.UNSCOPED_TOKEN,
            headers={'X-Subject-Token': saml2_fixtures.UNSCOPED_TOKEN_HEADER,
                     'Content-Type': 'application/json'})

        self.session.redirect = False
        response = self.saml2plugin.get_auth_ref(self.session)
        self.assertEqual(saml2_fixtures.UNSCOPED_TOKEN_HEADER,
                         response.auth_token)


class AuthenticateviaADFSTests(base.TestCase):

    GROUP = 'auth'

    NAMESPACES = {
        's': 'http://www.w3.org/2003/05/soap-envelope',
        'trust': 'http://docs.oasis-open.org/ws-sx/ws-trust/200512',
        'wsa': 'http://www.w3.org/2005/08/addressing',
        'wsp': 'http://schemas.xmlsoap.org/ws/2004/09/policy',
        'a': 'http://www.w3.org/2005/08/addressing',
        'o': ('http://docs.oasis-open.org/wss/2004/01/oasis'
              '-200401-wss-wssecurity-secext-1.0.xsd')
    }

    USER_XPATH = ('/s:Envelope/s:Header'
                  '/o:Security'
                  '/o:UsernameToken'
                  '/o:Username')
    PASSWORD_XPATH = ('/s:Envelope/s:Header'
                      '/o:Security'
                      '/o:UsernameToken'
                      '/o:Password')
    ADDRESS_XPATH = ('/s:Envelope/s:Body'
                     '/trust:RequestSecurityToken'
                     '/wsp:AppliesTo/wsa:EndpointReference'
                     '/wsa:Address')
    TO_XPATH = ('/s:Envelope/s:Header'
                '/a:To')

    TEST_TOKEN = uuid.uuid4().hex

    PROTOCOL = 'saml2'

    @property
    def _uuid4(self):
        return '4b911420-4982-4009-8afc-5c596cd487f5'

    def setUp(self):
        super(AuthenticateviaADFSTests, self).setUp()

        self.register_conf_options(group=self.GROUP)

        self.IDENTITY_PROVIDER = 'adfs'
        self.IDENTITY_PROVIDER_URL = ('http://adfs.local/adfs/service/trust/13'
                                      '/usernamemixed')
        self.FEDERATION_AUTH_URL = '%s/%s' % (
            self.TEST_URL,
            'OS-FEDERATION/identity_providers/adfs/protocols/saml2/auth')
        self.SP_ENDPOINT = 'https://openstack4.local/Shibboleth.sso/ADFS'

        self.adfsplugin = saml2.ADFSToken(
            self.TEST_URL, self.IDENTITY_PROVIDER,
            self.IDENTITY_PROVIDER_URL, self.SP_ENDPOINT,
            self.TEST_USER, self.TEST_TOKEN, self.PROTOCOL)

        self.ADFS_SECURITY_TOKEN_RESPONSE = _load_xml(
            'ADFS_RequestSecurityTokenResponse.xml')
        self.ADFS_FAULT = _load_xml('ADFS_fault.xml')

    def test_get_adfs_security_token(self):
        """Test ADFSToken._get_adfs_security_token()."""

        self.requests.register_uri(
            'POST', self.IDENTITY_PROVIDER_URL,
            content=make_oneline(self.ADFS_SECURITY_TOKEN_RESPONSE),
            status_code=200)

        self.adfsplugin._prepare_adfs_request()
        self.adfsplugin._get_adfs_security_token(self.session)

        adfs_response = etree.tostring(self.adfsplugin.adfs_token)
        fixture_response = self.ADFS_SECURITY_TOKEN_RESPONSE

        self.assertEqual(fixture_response, adfs_response)

    def test_adfs_request_user(self):
        self.adfsplugin._prepare_adfs_request()
        user = self.adfsplugin.prepared_request.xpath(
            self.USER_XPATH, namespaces=self.NAMESPACES)[0]
        self.assertEqual(self.TEST_USER, user.text)

    def test_adfs_request_password(self):
        self.adfsplugin._prepare_adfs_request()
        password = self.adfsplugin.prepared_request.xpath(
            self.PASSWORD_XPATH, namespaces=self.NAMESPACES)[0]
        self.assertEqual(self.TEST_TOKEN, password.text)

    def test_adfs_request_to(self):
        self.adfsplugin._prepare_adfs_request()
        to = self.adfsplugin.prepared_request.xpath(
            self.TO_XPATH, namespaces=self.NAMESPACES)[0]
        self.assertEqual(self.IDENTITY_PROVIDER_URL, to.text)

    def test_prepare_adfs_request_address(self):
        self.adfsplugin._prepare_adfs_request()
        address = self.adfsplugin.prepared_request.xpath(
            self.ADDRESS_XPATH, namespaces=self.NAMESPACES)[0]
        self.assertEqual(self.SP_ENDPOINT, address.text)

    def test_prepare_sp_request(self):
        assertion = etree.XML(self.ADFS_SECURITY_TOKEN_RESPONSE)
        assertion = assertion.xpath(
            saml2.ADFSToken.ADFS_ASSERTION_XPATH,
            namespaces=saml2.ADFSToken.ADFS_TOKEN_NAMESPACES)
        assertion = assertion[0]
        assertion = etree.tostring(assertion)

        assertion = assertion.replace(
            b'http://docs.oasis-open.org/ws-sx/ws-trust/200512',
            b'http://schemas.xmlsoap.org/ws/2005/02/trust')
        assertion = urllib.parse.quote(assertion)
        assertion = 'wa=wsignin1.0&wresult=' + assertion

        self.adfsplugin.adfs_token = etree.XML(
            self.ADFS_SECURITY_TOKEN_RESPONSE)
        self.adfsplugin._prepare_sp_request()

        self.assertEqual(assertion, self.adfsplugin.encoded_assertion)

    def test_get_adfs_security_token_authn_fail(self):
        """Test proper parsing XML fault after bad authentication.

        An exceptions.AuthorizationFailure should be raised including
        error message from the XML message indicating where was the problem.
        """
        self.requests.register_uri('POST',
                                   self.IDENTITY_PROVIDER_URL,
                                   content=make_oneline(self.ADFS_FAULT),
                                   status_code=500)

        self.adfsplugin._prepare_adfs_request()
        self.assertRaises(exceptions.AuthorizationFailure,
                          self.adfsplugin._get_adfs_security_token,
                          self.session)
        # TODO(marek-denis): Python3 tests complain about missing 'message'
        # attributes
        # self.assertEqual('a:FailedAuthentication', e.message)

    def test_get_adfs_security_token_bad_response(self):
        """Test proper handling HTTP 500 and mangled (non XML) response.

        This should never happen yet, keystoneauth1 should be prepared
        and correctly raise exceptions.InternalServerError once it cannot
        parse XML fault message
        """
        self.requests.register_uri('POST',
                                   self.IDENTITY_PROVIDER_URL,
                                   content=b'NOT XML',
                                   status_code=500)
        self.adfsplugin._prepare_adfs_request()
        self.assertRaises(exceptions.InternalServerError,
                          self.adfsplugin._get_adfs_security_token,
                          self.session)

    # TODO(marek-denis): Need to figure out how to properly send cookies
    # from the request_uri() method.
    def _send_assertion_to_service_provider(self):
        """Test whether SP issues a cookie."""
        cookie = uuid.uuid4().hex

        self.requests.register_uri('POST', self.SP_ENDPOINT,
                                   headers={"set-cookie": cookie},
                                   status_code=302)

        self.adfsplugin.adfs_token = self._build_adfs_request()
        self.adfsplugin._prepare_sp_request()
        self.adfsplugin._send_assertion_to_service_provider(self.session)

        self.assertEqual(1, len(self.session.session.cookies))

    def test_send_assertion_to_service_provider_bad_status(self):
        self.requests.register_uri('POST', self.SP_ENDPOINT,
                                   status_code=500)

        self.adfsplugin.adfs_token = etree.XML(
            self.ADFS_SECURITY_TOKEN_RESPONSE)
        self.adfsplugin._prepare_sp_request()

        self.assertRaises(
            exceptions.InternalServerError,
            self.adfsplugin._send_assertion_to_service_provider,
            self.session)

    def test_access_sp_no_cookies_fail(self):
        # clean cookie jar
        self.session.session.cookies = []

        self.assertRaises(exceptions.AuthorizationFailure,
                          self.adfsplugin._access_service_provider,
                          self.session)

    def test_check_valid_token_when_authenticated(self):
        self.requests.register_uri(
            'GET', self.FEDERATION_AUTH_URL,
            json=saml2_fixtures.UNSCOPED_TOKEN,
            headers=client_fixtures.AUTH_RESPONSE_HEADERS)

        self.session.session.cookies = [object()]
        self.adfsplugin._access_service_provider(self.session)
        response = self.adfsplugin.authenticated_response

        self.assertEqual(client_fixtures.AUTH_RESPONSE_HEADERS,
                         response.headers)

        self.assertEqual(saml2_fixtures.UNSCOPED_TOKEN['token'],
                         response.json()['token'])

    def test_end_to_end_workflow(self):
        self.requests.register_uri(
            'POST', self.IDENTITY_PROVIDER_URL,
            content=self.ADFS_SECURITY_TOKEN_RESPONSE,
            status_code=200)
        self.requests.register_uri(
            'POST', self.SP_ENDPOINT,
            headers={"set-cookie": 'x'},
            status_code=302)
        self.requests.register_uri(
            'GET', self.FEDERATION_AUTH_URL,
            json=saml2_fixtures.UNSCOPED_TOKEN,
            headers=client_fixtures.AUTH_RESPONSE_HEADERS)

        # NOTE(marek-denis): We need to mimic this until self.requests can
        # issue cookies properly.
        self.session.session.cookies = [object()]
        token = self.adfsplugin.get_auth_ref(self.session)
        self.assertEqual(client_fixtures.AUTH_SUBJECT_TOKEN, token.auth_token)
