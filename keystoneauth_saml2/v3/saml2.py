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

import logging

from keystoneauth1 import access
from keystoneauth1 import exceptions
from lxml import etree

from keystoneauth_saml2.v3 import base

LOG = logging.getLogger(__name__)


def _first(_list):
    if len(_list) != 1:
        raise IndexError('Only single element list is acceptable')
    return _list[0]


class _Response(object):

    ECP_SAML2_NAMESPACES = {
        'ecp': 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp',
        'S': 'http://schemas.xmlsoap.org/soap/envelope/',
        'paos': 'urn:liberty:paos:2003-08'
    }

    def __init__(self, text):
        self.data = etree.XML(text)

    @property
    def consumer_url(self):
        u = self.data.xpath(self.URL_XP, namespaces=self.ECP_SAML2_NAMESPACES)
        return _first(u) if u else None

    def to_string(self):
        return etree.tostring(self.data)


class _SPResponse(_Response):

    SAML2_HEADER_INDEX = 0

    ECP_RELAY_STATE = '//ecp:RelayState'

    URL_XP = '/S:Envelope/S:Header/paos:Request/@responseConsumerURL'

    @property
    def relay_state(self):
        return _first(self.data.xpath(self.ECP_RELAY_STATE,
                                      namespaces=self.ECP_SAML2_NAMESPACES))

    def prepare(self):
        self.data.remove(self.data[self.SAML2_HEADER_INDEX])


class _IDPResponse(_Response):

    URL_XP = '/S:Envelope/S:Header/ecp:Response/@AssertionConsumerServiceURL'

    @property
    def relay_state(self):
        return self.data[0][0]

    @relay_state.setter
    def relay_state(self, value):
        self.data[0][0] = value


class Saml2Token(base._BaseSAMLPlugin):
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

    _auth_method_class = base.Saml2TokenAuthMethod

    ECP_SP_EMPTY_REQUEST_HEADERS = {
        'Accept': 'text/html, application/vnd.paos+xml',
        'PAOS': ('ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:'
                 'SAML:2.0:profiles:SSO:ecp"')
    }

    ECP_SP_SAML2_REQUEST_HEADERS = {
        'Content-Type': 'application/vnd.paos+xml'
    }

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

    def _post_idp(self, session, sp_response):
        """Present modified SAML2 authn assertion from the Service Provider."""
        sp_response.prepare()

        # Currently HTTPBasicAuth method is hardcoded into the plugin
        response = session.post(
            self.identity_provider_url,
            headers={'Content-type': 'text/xml'},
            data=sp_response.to_string(),
            requests_auth=(self.username, self.password),
            authenticated=False,
            log=False)

        idp_response = _IDPResponse(response.content)

        # NOTE(jamielennox): In the initial SAML2 authn Request issued by a
        # Service Provider there is a url called ``consumer url``. A trusted
        # Identity Provider should issue identical url. If the URLs are not
        # equal the federated authn process should be interrupted and the user
        # should be warned.
        if sp_response.consumer_url != idp_response.consumer_url:
            # send fault message to the SP, discard the response
            session.post(sp_response.consumer_url,
                         data=self.SOAP_FAULT,
                         headers=self.ECP_SP_SAML2_REQUEST_HEADERS,
                         authenticated=False)

            # prepare error message and raise an exception.
            msg = ('Consumer URLs from Service Provider %(service_provider)s '
                   '%(sp_consumer_url)s and Identity Provider '
                   '%(identity_provider)s %(idp_consumer_url)s are not equal')
            msg = msg % {
                'service_provider': self.federated_token_url,
                'sp_consumer_url': sp_response.consumer_url,
                'identity_provider': self.identity_provider,
                'idp_consumer_url': idp_response.consumer_url
            }

            raise exceptions.AuthorizationFailure(msg)

        return idp_response

    def _post_sp(self, session, sp_response, idp_response):
        idp_response.relay_state = sp_response.relay_state

        response = session.post(
            idp_response.consumer_url,
            headers=self.ECP_SP_SAML2_REQUEST_HEADERS,
            data=idp_response.to_string(),
            authenticated=False,
            redirect=False)

        # Don't follow HTTP specs - after the HTTP 302/303 response don't
        # repeat the call directed to the Location URL. In this case, this is
        # an indication that saml2 session is now active and protected resource
        # can be accessed.
        if response.status_code not in (self.HTTP_MOVED_TEMPORARILY,
                                        self.HTTP_SEE_OTHER):
            return response

        return session.get(response.headers['location'],
                           authenticated=False,
                           headers=self.ECP_SP_SAML2_REQUEST_HEADERS)

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
        response = session.get(self.federated_token_url,
                               headers=self.ECP_SP_EMPTY_REQUEST_HEADERS,
                               authenticated=False)

        # This may happen if you are already logged in
        if 'X-Subject-Token' in response.headers:
            return access.create(resp=response)

        try:
            sp_response = _SPResponse(response.content)
        except etree.XMLSyntaxError as e:
            msg = ('SAML2: Error parsing XML returned '
                   'from Service Provider, reason: %s') % e
            raise exceptions.AuthorizationFailure(msg)

        try:
            idp_response = self._post_idp(session, sp_response)
        except etree.XMLSyntaxError as e:
            msg = ('SAML2: Error parsing XML returned '
                   'from Identity Provider, reason: %s') % e
            raise exceptions.AuthorizationFailure(msg)

        response = self._post_sp(session, sp_response, idp_response)
        return access.create(resp=response)
