# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import datetime
import logging
import uuid

from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1.identity import v3
from keystoneauth1.identity.v3 import federation
from lxml import etree
from six.moves import urllib


LOG = logging.getLogger(__name__)


class _BaseSAMLPlugin(federation.FederationBaseAuth):

    HTTP_MOVED_TEMPORARILY = 302
    HTTP_SEE_OTHER = 303

    def __init__(self, auth_url,
                 identity_provider, identity_provider_url,
                 username, password, protocol,
                 **kwargs):
        """Class constructor accepting following parameters:

        :param auth_url: URL of the Identity Service
        :type auth_url: string

        :param identity_provider: Name of the Identity Provider the client
                                  will authenticate against. This parameter
                                  will be used to build a dynamic URL used to
                                  obtain unscoped OpenStack token.
        :type identity_provider: string

        :param identity_provider_url: An Identity Provider URL, where the SAML2
                                      authn request will be sent.
        :type identity_provider_url: string

        :param username: User's login
        :type username: string

        :param password: User's password
        :type password: string

        :param protocol: Protocol to be used for the authentication.
                         The name must be equal to one configured at the
                         keystone sp side. This value is used for building
                         dynamic authentication URL.
                         Typical value would be: saml2
        :type protocol: string

        """
        super(_BaseSAMLPlugin, self).__init__(
            auth_url=auth_url, identity_provider=identity_provider,
            protocol=protocol,
            **kwargs)
        self.identity_provider_url = identity_provider_url
        self.username = username
        self.password = password

    @staticmethod
    def _first(_list):
        if len(_list) != 1:
            raise IndexError('Only single element list is acceptable')
        return _list[0]

    @staticmethod
    def str_to_xml(content, msg=None, include_exc=True):
        try:
            return etree.XML(content)
        except etree.XMLSyntaxError as e:
            if not msg:
                msg = str(e)
            else:
                msg = msg % e if include_exc else msg
            raise exceptions.AuthorizationFailure(msg)

    @staticmethod
    def xml_to_str(content, **kwargs):
        return etree.tostring(content, **kwargs)


class Saml2TokenAuthMethod(v3.AuthMethod):
    _method_parameters = []

    def get_auth_data(self, session, auth, headers, **kwargs):
        raise exceptions.MethodNotImplemented('This method should never '
                                              'be called')


class Saml2Token(_BaseSAMLPlugin):
    """Implement authentication plugin for SAML2 protocol.

    ECP stands for `Enhanced Client or Proxy` and is a SAML2 extension
    for federated authentication where a transportation layer consists of
    HTTP protocol and XML SOAP messages.

    `Read for more information
    <https://wiki.shibboleth.net/confluence/display/SHIB2/ECP>`_ on ECP.

    Reference the `SAML2 ECP specification <https://www.oasis-open.org/\
    committees/download.php/49979/saml-ecp-v2.0-wd09.pdf>`_.

    Currently only HTTPBasicAuth mechanism is available for the IdP
    authenication.

    :param auth_url: URL of the Identity Service
    :type auth_url: string

    :param identity_provider: name of the Identity Provider the client will
                              authenticate against. This parameter will be used
                              to build a dynamic URL used to obtain unscoped
                              OpenStack token.
    :type identity_provider: string

    :param identity_provider_url: An Identity Provider URL, where the SAML2
                                  authn request will be sent.
    :type identity_provider_url: string

    :param username: User's login
    :type username: string

    :param password: User's password
    :type password: string


    :param protocol: Protocol to be used for the authentication.
                     The name must be equal to one configured at the
                     keystone sp side. This value is used for building
                     dynamic authentication URL.
                     Typical value  would be: saml2
    :type protocol: string

    """

    _auth_method_class = Saml2TokenAuthMethod

    SAML2_HEADER_INDEX = 0
    ECP_SP_EMPTY_REQUEST_HEADERS = {
        'Accept': 'text/html, application/vnd.paos+xml',
        'PAOS': ('ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:'
                 'SAML:2.0:profiles:SSO:ecp"')
    }

    ECP_SP_SAML2_REQUEST_HEADERS = {
        'Content-Type': 'application/vnd.paos+xml'
    }

    ECP_SAML2_NAMESPACES = {
        'ecp': 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp',
        'S': 'http://schemas.xmlsoap.org/soap/envelope/',
        'paos': 'urn:liberty:paos:2003-08'
    }

    ECP_RELAY_STATE = '//ecp:RelayState'

    ECP_SERVICE_PROVIDER_CONSUMER_URL = ('/S:Envelope/S:Header/paos:Request/'
                                         '@responseConsumerURL')

    ECP_IDP_CONSUMER_URL = ('/S:Envelope/S:Header/ecp:Response/'
                            '@AssertionConsumerServiceURL')

    SOAP_FAULT = """
    <S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
       <S:Body>
         <S:Fault>
            <faultcode>S:Server</faultcode>
            <faultstring>responseConsumerURL from SP and
            assertionConsumerServiceURL from IdP do not match
            </faultstring>
         </S:Fault>
       </S:Body>
    </S:Envelope>
    """

    def _handle_http_ecp_redirect(self, session, response, method, **kwargs):
        if response.status_code not in (self.HTTP_MOVED_TEMPORARILY,
                                        self.HTTP_SEE_OTHER):
            return response

        location = response.headers['location']
        return session.request(location, method, authenticated=False,
                               **kwargs)

    def _prepare_idp_saml2_request(self, saml2_authn_request):
        header = saml2_authn_request[self.SAML2_HEADER_INDEX]
        saml2_authn_request.remove(header)

    def _check_consumer_urls(self, session, sp_response_consumer_url,
                             idp_sp_response_consumer_url):
        """Check if consumer URLs issued by SP and IdP are equal.

        In the initial SAML2 authn Request issued by a Service Provider
        there is a url called ``consumer url``. A trusted Identity Provider
        should issue identical url. If the URLs are not equal the federated
        authn process should be interrupted and the user should be warned.

        :param session: session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session
        :param sp_response_consumer_url: consumer URL issued by a SP
        :type  sp_response_consumer_url: string
        :param idp_sp_response_consumer_url: consumer URL issued by an IdP
        :type idp_sp_response_consumer_url: string

        """
        if sp_response_consumer_url != idp_sp_response_consumer_url:
            # send fault message to the SP, discard the response
            session.post(sp_response_consumer_url, data=self.SOAP_FAULT,
                         headers=self.ECP_SP_SAML2_REQUEST_HEADERS,
                         authenticated=False)

            # prepare error message and raise an exception.
            msg = ('Consumer URLs from Service Provider %(service_provider)s '
                   '%(sp_consumer_url)s and Identity Provider '
                   '%(identity_provider)s %(idp_consumer_url)s are not equal')
            msg = msg % {
                'service_provider': self.federated_token_url,
                'sp_consumer_url': sp_response_consumer_url,
                'identity_provider': self.identity_provider,
                'idp_consumer_url': idp_sp_response_consumer_url
            }

            raise exceptions.AuthorizationFailure(msg)

    def _send_service_provider_request(self, session):
        """Initial HTTP GET request to the SAML2 protected endpoint.

        It's crucial to include HTTP headers indicating that the client is
        willing to take advantage of the ECP SAML2 extension and receive data
        as the SOAP.
        Unlike standard authentication methods in the OpenStack Identity,
        the client accesses::
        ``/v3/OS-FEDERATION/identity_providers/{identity_providers}/
        protocols/{protocol}/auth``

        After a successful HTTP call the HTTP response should include SAML2
        authn request in the XML format.

        If a HTTP response contains ``X-Subject-Token`` in the headers and
        the response body is a valid JSON assume the user was already
        authenticated and Keystone returned a valid unscoped token.
        Return True indicating the user was already authenticated.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        """
        sp_response = session.get(self.federated_token_url,
                                  headers=self.ECP_SP_EMPTY_REQUEST_HEADERS,
                                  authenticated=False)

        if 'X-Subject-Token' in sp_response.headers:
            self.authenticated_response = sp_response
            return True

        try:
            self.saml2_authn_request = etree.XML(sp_response.content)
        except etree.XMLSyntaxError as e:
            msg = ('SAML2: Error parsing XML returned '
                   'from Service Provider, reason: %s') % e
            raise exceptions.AuthorizationFailure(msg)

        relay_state = self.saml2_authn_request.xpath(
            self.ECP_RELAY_STATE, namespaces=self.ECP_SAML2_NAMESPACES)
        self.relay_state = self._first(relay_state)

        sp_response_consumer_url = self.saml2_authn_request.xpath(
            self.ECP_SERVICE_PROVIDER_CONSUMER_URL,
            namespaces=self.ECP_SAML2_NAMESPACES)
        self.sp_response_consumer_url = self._first(sp_response_consumer_url)
        return False

    def _send_idp_saml2_authn_request(self, session):
        """Present modified SAML2 authn assertion from the Service Provider."""

        self._prepare_idp_saml2_request(self.saml2_authn_request)
        idp_saml2_authn_request = self.saml2_authn_request

        # Currently HTTPBasicAuth method is hardcoded into the plugin
        idp_response = session.post(
            self.identity_provider_url,
            headers={'Content-type': 'text/xml'},
            data=etree.tostring(idp_saml2_authn_request),
            requests_auth=(self.username, self.password),
            authenticated=False, log=False)

        try:
            self.saml2_idp_authn_response = etree.XML(idp_response.content)
        except etree.XMLSyntaxError as e:
            msg = ('SAML2: Error parsing XML returned '
                   'from Identity Provider, reason: %s') % e
            raise exceptions.AuthorizationFailure(msg)

        idp_response_consumer_url = self.saml2_idp_authn_response.xpath(
            self.ECP_IDP_CONSUMER_URL,
            namespaces=self.ECP_SAML2_NAMESPACES)

        self.idp_response_consumer_url = self._first(idp_response_consumer_url)

        self._check_consumer_urls(session, self.idp_response_consumer_url,
                                  self.sp_response_consumer_url)

    def _send_service_provider_saml2_authn_response(self, session):
        """Present SAML2 assertion to the Service Provider.

        The assertion is issued by a trusted Identity Provider for the
        authenticated user. This function directs the HTTP request to SP
        managed URL, for instance: ``https://<host>:<port>/Shibboleth.sso/
        SAML2/ECP``.
        Upon success the there's a session created and access to the protected
        resource is granted. Many implementations of the SP return HTTP 302
        status code pointing to the protected URL (``https://<host>:<port>/v3/
        OS-FEDERATION/identity_providers/{identity_provider}/protocols/
        {protocol_id}/auth`` in this case). Saml2 plugin should point to that
        URL again, with HTTP GET method, expecting an unscoped token.

        :param session: a session object to send out HTTP requests.

        """
        self.saml2_idp_authn_response[0][0] = self.relay_state

        response = session.post(
            self.idp_response_consumer_url,
            headers=self.ECP_SP_SAML2_REQUEST_HEADERS,
            data=etree.tostring(self.saml2_idp_authn_response),
            authenticated=False, redirect=False)

        # Don't follow HTTP specs - after the HTTP 302/303 response don't
        # repeat the call directed to the Location URL. In this case, this is
        # an indication that saml2 session is now active and protected resource
        # can be accessed.
        response = self._handle_http_ecp_redirect(
            session, response, method='GET',
            headers=self.ECP_SP_SAML2_REQUEST_HEADERS)

        self.authenticated_response = response

    def get_unscoped_auth_ref(self, session):
        """Get unscoped OpenStack token after federated authentication.

        This is a multi-step process including multiple HTTP requests.

        The federated authentication consists of:

        * HTTP GET request to the Identity Service (acting as a Service
          Provider).

          It's crucial to include HTTP headers indicating we are expecting SOAP
          message in return. Service Provider should respond with such SOAP
          message.  This step is handed by a method
          ``Saml2Token_send_service_provider_request()``.

        * HTTP POST request to the external Identity Provider service with
          ECP extension enabled. The content sent is a header removed SOAP
          message  returned from the Service Provider. It's also worth noting
          that ECP extension to the SAML2 doesn't define authentication method.
          The most popular is HttpBasicAuth with just user and password.
          Other possibilities could be X509 certificates or Kerberos.
          Upon successful authentication the user should receive a SAML2
          assertion.
          This step is handed by a method
          ``Saml2Token_send_idp_saml2_authn_request(session)``

        * HTTP POST request again to the Service Provider. The body of the
          request includes SAML2 assertion issued by a trusted Identity
          Provider. The request should be sent to the Service Provider
          consumer url specified in the SAML2 assertion.
          Providing the authentication was successful and both Service Provider
          and Identity Providers are trusted to each other, the Service
          Provider will issue an unscoped token with a list of groups the
          federated user is a member of.
          This step is handed by a method
          ``Saml2Token_send_service_provider_saml2_authn_response()``

          Unscoped token example::

            {
                "token": {
                    "methods": [
                        "saml2"
                    ],
                    "user": {
                        "id": "username%40example.com",
                        "name": "username@example.com",
                        "OS-FEDERATION": {
                            "identity_provider": "ACME",
                            "protocol": "saml2",
                            "groups": [
                                {"id": "abc123"},
                                {"id": "bcd234"}
                            ]
                        }
                    }
                }
            }


        :param session : a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :returns: AccessInfo
        :rtype: :py:class:`keystoneauth1.access.AccessInfo`
        """
        saml_authenticated = self._send_service_provider_request(session)
        if not saml_authenticated:
            self._send_idp_saml2_authn_request(session)
            self._send_service_provider_saml2_authn_response(session)

        return access.create(resp=self.authenticated_response)


class ADFSToken(_BaseSAMLPlugin):
    """Authentication plugin for Microsoft ADFS2.0 IdPs."""

    _auth_method_class = Saml2TokenAuthMethod

    DEFAULT_ADFS_TOKEN_EXPIRATION = 120

    HEADER_SOAP = {"Content-Type": "application/soap+xml; charset=utf-8"}
    HEADER_X_FORM = {"Content-Type": "application/x-www-form-urlencoded"}

    NAMESPACES = {
        's': 'http://www.w3.org/2003/05/soap-envelope',
        'a': 'http://www.w3.org/2005/08/addressing',
        'u': ('http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
              'wss-wssecurity-utility-1.0.xsd')
    }

    ADFS_TOKEN_NAMESPACES = {
        's': 'http://www.w3.org/2003/05/soap-envelope',
        't': 'http://docs.oasis-open.org/ws-sx/ws-trust/200512'
    }
    ADFS_ASSERTION_XPATH = ('/s:Envelope/s:Body'
                            '/t:RequestSecurityTokenResponseCollection'
                            '/t:RequestSecurityTokenResponse')

    def __init__(self, auth_url, identity_provider, identity_provider_url,
                 service_provider_endpoint, username, password,
                 protocol, **kwargs):
        """Constructor for ``ADFSToken``.

        :param auth_url: URL of the Identity Service
        :type auth_url: string

        :param identity_provider: name of the Identity Provider the client
                                  will authenticate against. This parameter
                                  will be used to build a dynamic URL used to
                                  obtain unscoped OpenStack token.
        :type identity_provider: string

        :param identity_provider_url: An Identity Provider URL, where the SAML2
                                      authentication request will be sent.
        :type identity_provider_url: string

        :param service_provider_endpoint: Endpoint where an assertion is being
            sent, for instance: ``https://host.domain/Shibboleth.sso/ADFS``
        :type service_provider_endpoint: string

        :param username: User's login
        :type username: string

        :param password: User's password
        :type password: string

        """

        super(ADFSToken, self).__init__(
            auth_url=auth_url, identity_provider=identity_provider,
            identity_provider_url=identity_provider_url,
            username=username, password=password, protocol=protocol)

        self.service_provider_endpoint = service_provider_endpoint

    def _cookies(self, session):
        """Check if cookie jar is not empty.

        keystoneauth1.session.Session object doesn't have a cookies attribute.
        We should then try fetching cookies from the underlying
        requests.Session object. If that fails too, there is something wrong
        and let Python raise the AttributeError.

        :param session
        :returns: True if cookie jar is nonempty, False otherwise
        :raises AttributeError: in case cookies are not find anywhere

        """
        try:
            return bool(session.cookies)
        except AttributeError:
            pass

        return bool(session.session.cookies)

    def _token_dates(self, fmt='%Y-%m-%dT%H:%M:%S.%fZ'):
        """Calculate created and expires datetime objects.

        The method is going to be used for building ADFS Request Security
        Token message. Time interval between ``created`` and ``expires``
        dates is now static and equals to 120 seconds. ADFS security tokens
        should not be live too long, as currently ``keystoneauth1``
        doesn't have mechanisms for reusing such tokens (every time ADFS authn
        method is called, keystoneauth1 will login with the ADFS instance).

        :param fmt: Datetime format for specifying string format of a date.
                    It should not be changed if the method is going to be used
                    for building the ADFS security token request.
        :type fmt: string

        """

        date_created = datetime.datetime.utcnow()
        date_expires = date_created + datetime.timedelta(
            seconds=self.DEFAULT_ADFS_TOKEN_EXPIRATION)
        return [_time.strftime(fmt) for _time in (date_created, date_expires)]

    def _prepare_adfs_request(self):
        """Build the ADFS Request Security Token SOAP message.

        Some values like username or password are inserted in the request.

        """

        WSS_SECURITY_NAMESPACE = {
            'o': ('http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
                  'wss-wssecurity-secext-1.0.xsd')
        }

        TRUST_NAMESPACE = {
            'trust': 'http://docs.oasis-open.org/ws-sx/ws-trust/200512'
        }

        WSP_NAMESPACE = {
            'wsp': 'http://schemas.xmlsoap.org/ws/2004/09/policy'
        }

        WSA_NAMESPACE = {
            'wsa': 'http://www.w3.org/2005/08/addressing'
        }

        root = etree.Element(
            '{http://www.w3.org/2003/05/soap-envelope}Envelope',
            nsmap=self.NAMESPACES)

        header = etree.SubElement(
            root, '{http://www.w3.org/2003/05/soap-envelope}Header')
        action = etree.SubElement(
            header, "{http://www.w3.org/2005/08/addressing}Action")
        action.set(
            "{http://www.w3.org/2003/05/soap-envelope}mustUnderstand", "1")
        action.text = ('http://docs.oasis-open.org/ws-sx/ws-trust/200512'
                       '/RST/Issue')

        messageID = etree.SubElement(
            header, '{http://www.w3.org/2005/08/addressing}MessageID')
        messageID.text = 'urn:uuid:' + uuid.uuid4().hex
        replyID = etree.SubElement(
            header, '{http://www.w3.org/2005/08/addressing}ReplyTo')
        address = etree.SubElement(
            replyID, '{http://www.w3.org/2005/08/addressing}Address')
        address.text = 'http://www.w3.org/2005/08/addressing/anonymous'

        to = etree.SubElement(
            header, '{http://www.w3.org/2005/08/addressing}To')
        to.set("{http://www.w3.org/2003/05/soap-envelope}mustUnderstand", "1")

        security = etree.SubElement(
            header, '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
            'wss-wssecurity-secext-1.0.xsd}Security',
            nsmap=WSS_SECURITY_NAMESPACE)

        security.set(
            "{http://www.w3.org/2003/05/soap-envelope}mustUnderstand", "1")

        timestamp = etree.SubElement(
            security, ('{http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
                       'wss-wssecurity-utility-1.0.xsd}Timestamp'))
        timestamp.set(
            ('{http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
             'wss-wssecurity-utility-1.0.xsd}Id'), '_0')

        created = etree.SubElement(
            timestamp, ('{http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
                        'wss-wssecurity-utility-1.0.xsd}Created'))

        expires = etree.SubElement(
            timestamp, ('{http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
                        'wss-wssecurity-utility-1.0.xsd}Expires'))

        created.text, expires.text = self._token_dates()

        usernametoken = etree.SubElement(
            security, '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
                      'wss-wssecurity-secext-1.0.xsd}UsernameToken')
        usernametoken.set(
            ('{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-'
             'wssecurity-utility-1.0.xsd}u'), "uuid-%s-1" % uuid.uuid4().hex)

        username = etree.SubElement(
            usernametoken, ('{http://docs.oasis-open.org/wss/2004/01/oasis-'
                            '200401-wss-wssecurity-secext-1.0.xsd}Username'))
        password = etree.SubElement(
            usernametoken, ('{http://docs.oasis-open.org/wss/2004/01/oasis-'
                            '200401-wss-wssecurity-secext-1.0.xsd}Password'),
            Type=('http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-'
                  'username-token-profile-1.0#PasswordText'))

        body = etree.SubElement(
            root, "{http://www.w3.org/2003/05/soap-envelope}Body")

        request_security_token = etree.SubElement(
            body, ('{http://docs.oasis-open.org/ws-sx/ws-trust/200512}'
                   'RequestSecurityToken'), nsmap=TRUST_NAMESPACE)

        applies_to = etree.SubElement(
            request_security_token,
            '{http://schemas.xmlsoap.org/ws/2004/09/policy}AppliesTo',
            nsmap=WSP_NAMESPACE)

        endpoint_reference = etree.SubElement(
            applies_to,
            '{http://www.w3.org/2005/08/addressing}EndpointReference',
            nsmap=WSA_NAMESPACE)

        wsa_address = etree.SubElement(
            endpoint_reference,
            '{http://www.w3.org/2005/08/addressing}Address')

        keytype = etree.SubElement(
            request_security_token,
            '{http://docs.oasis-open.org/ws-sx/ws-trust/200512}KeyType')
        keytype.text = ('http://docs.oasis-open.org/ws-sx/'
                        'ws-trust/200512/Bearer')

        request_type = etree.SubElement(
            request_security_token,
            '{http://docs.oasis-open.org/ws-sx/ws-trust/200512}RequestType')
        request_type.text = ('http://docs.oasis-open.org/ws-sx/'
                             'ws-trust/200512/Issue')
        token_type = etree.SubElement(
            request_security_token,
            '{http://docs.oasis-open.org/ws-sx/ws-trust/200512}TokenType')
        token_type.text = 'urn:oasis:names:tc:SAML:1.0:assertion'

        # After constructing the request, let's plug in some values
        username.text = self.username
        password.text = self.password
        to.text = self.identity_provider_url
        wsa_address.text = self.service_provider_endpoint

        self.prepared_request = root

    def _get_adfs_security_token(self, session):
        """Send ADFS Security token to the ADFS server.

        Store the result in the instance attribute and raise an exception in
        case the response is not valid XML data.

        If a user cannot authenticate due to providing bad credentials, the
        ADFS2.0 server will return a HTTP 500 response and a XML Fault message.
        If ``exceptions.InternalServerError`` is caught, the method tries to
        parse the XML response.
        If parsing is unsuccessful, an ``exceptions.AuthorizationFailure`` is
        raised with a reason from the XML fault. Otherwise an original
        ``exceptions.InternalServerError`` is re-raised.

        :param session : a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :raises keystoneauth1.exceptions.AuthorizationFailure: when HTTP
                 response from the ADFS server is not a valid XML ADFS security
                 token.
        :raises keystoneauth1.exceptions.InternalServerError: If response
                 status code is HTTP 500 and the response XML cannot be
                 recognized.

        """
        def _get_failure(e):
            xpath = '/s:Envelope/s:Body/s:Fault/s:Code/s:Subcode/s:Value'
            content = e.response.content
            try:
                obj = self.str_to_xml(content).xpath(
                    xpath, namespaces=self.NAMESPACES)
                obj = self._first(obj)
                return obj.text
            # NOTE(marek-denis): etree.Element.xpath() doesn't raise an
            # exception, it just returns an empty list. In that case, _first()
            # will raise IndexError and we should treat it as an indication XML
            # is not valid. exceptions.AuthorizationFailure can be raised from
            # str_to_xml(), however since server returned HTTP 500 we should
            # re-raise exceptions.InternalServerError.
            except (IndexError, exceptions.AuthorizationFailure):
                raise e

        request_security_token = self.xml_to_str(self.prepared_request)
        try:
            response = session.post(
                url=self.identity_provider_url, headers=self.HEADER_SOAP,
                data=request_security_token, authenticated=False)
        except exceptions.InternalServerError as e:
            reason = _get_failure(e)
            raise exceptions.AuthorizationFailure(reason)
        msg = ('Error parsing XML returned from '
               'the ADFS Identity Provider, reason: %s')
        self.adfs_token = self.str_to_xml(response.content, msg)

    def _prepare_sp_request(self):
        """Prepare ADFS Security Token to be sent to the Service Provider.

        The method works as follows:
        * Extract SAML2 assertion from the ADFS Security Token.
        * Replace namespaces
        * urlencode assertion
        * concatenate static string with the encoded assertion

        """
        assertion = self.adfs_token.xpath(
            self.ADFS_ASSERTION_XPATH, namespaces=self.ADFS_TOKEN_NAMESPACES)
        assertion = self._first(assertion)
        assertion = self.xml_to_str(assertion)
        # TODO(marek-denis): Ideally no string replacement should occur.
        # Unfortunately lxml doesn't allow for namespaces changing in-place and
        # probably the only solution good for now is to build the assertion
        # from scratch and reuse values from the adfs security token.
        assertion = assertion.replace(
            b'http://docs.oasis-open.org/ws-sx/ws-trust/200512',
            b'http://schemas.xmlsoap.org/ws/2005/02/trust')

        encoded_assertion = urllib.parse.quote(assertion)
        self.encoded_assertion = 'wa=wsignin1.0&wresult=' + encoded_assertion

    def _send_assertion_to_service_provider(self, session):
        """Send prepared assertion to a service provider.

        As the assertion doesn't contain a protected resource, the value from
        the ``location`` header is not valid and we should not let the Session
        object get redirected there. The aim of this call is to get a cookie in
        the response which is required for entering a protected endpoint.

        :param session : a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :raises: Corresponding HTTP error exception

        """
        session.post(
            url=self.service_provider_endpoint, data=self.encoded_assertion,
            headers=self.HEADER_X_FORM, redirect=False, authenticated=False)

    def _access_service_provider(self, session):
        """Access protected endpoint and fetch unscoped token.

        After federated authentication workflow a protected endpoint should be
        accessible with the session object. The access is granted basing on the
        cookies stored within the session object. If, for some reason no
        cookies are present (quantity test) it means something went wrong and
        user will not be able to fetch an unscoped token. In that case an
        ``exceptions.AuthorizationFailure` exception is raised and no HTTP call
        is even made.

        :param session : a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :raises keystoneauth1.exceptions.AuthorizationFailure: in case session
        object has empty cookie jar.

        """
        if self._cookies(session) is False:
            raise exceptions.AuthorizationFailure(
                "Session object doesn't contain a cookie, therefore you are "
                "not allowed to enter the Identity Provider's protected area.")
        self.authenticated_response = session.get(self.federated_token_url,
                                                  authenticated=False)

    def get_unscoped_auth_ref(self, session, *kwargs):
        """Retrieve unscoped token after authentcation with ADFS server.

        This is a multistep process:

        * Prepare ADFS Request Securty Token -
          build a etree.XML object filling certain attributes with proper user
          credentials, created/expires dates (ticket is be valid for 120
          seconds as currently we don't handle reusing ADFS issued security
          tokens).

        * Send ADFS Security token to the ADFS server. Step handled by

        * Receive and parse security token, extract actual SAML assertion and
          prepare a request addressed for the Service Provider endpoint.
          This also includes changing namespaces in the XML document. Step
          handled by ``ADFSToken._prepare_sp_request()`` method.

        * Send prepared assertion to the Service Provider endpoint. Usually
          the server will respond with HTTP 301 code which should be ignored as
          the 'location' header doesn't contain protected area. The goal of
          this operation is fetching the session cookie which later allows for
          accessing protected URL endpoints. Step handed by
          ``ADFSToken._send_assertion_to_service_provider()`` method.

        * Once the session cookie is issued, the protected endpoint can be
          accessed and an unscoped token can be retrieved. Step handled by
          ``ADFSToken._access_service_provider()`` method.

        :param session: a session object to send out HTTP requests.
        :type session: keystoneauth1.session.Session

        :returns: AccessInfo
        :rtype: :py:class:`keystoneauth1.access.AccessInfo`

        """
        self._prepare_adfs_request()
        self._get_adfs_security_token(session)
        self._prepare_sp_request()
        self._send_assertion_to_service_provider(session)
        self._access_service_provider(session)

        return access.create(resp=self.authenticated_response)
