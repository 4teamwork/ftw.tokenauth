from AccessControl.SecurityManagement import getSecurityManager
from AccessControl.SecurityManagement import newSecurityManager
from AccessControl.SecurityManagement import setSecurityManager
from ftw.tokenauth.oauth2.exceptions import VerificationError
from ftw.tokenauth.oauth2.jwt_grants import JWTBearerGrantProcessor
from ftw.tokenauth.pas.storage import CredentialStorage
from ftw.tokenauth.permissions import ImpersonateUser
from jwt.exceptions import InvalidTokenError
from plone import api
from Products.CMFCore.utils import getToolByName
from Products.Five.browser import BrowserView
import json
import jwt


JWT_BEARER_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'


class ErrorResponse(Exception):
    """Base class for error responses according to RFC 6749.
    """

    def __init__(self, msg, status=None):
        self.msg = msg
        self.status = status


class InvalidRequest(ErrorResponse):
    """Error response for invalid token requests (e.g. missing parameter).
    """

    error_type = 'invalid_request'


class InvalidGrant(ErrorResponse):
    """Error response for invalid grants (JWT not valid or expired).
    """

    error_type = 'invalid_grant'


class OAuth2TokenEndpoint(BrowserView):
    """OAuth2 token endpoint.

    Allows a client to exchange a JWT bearer authorization grant for a
    time-limited access token.

    The grant must be signed with the private key of a service key pair
    associated with the user that is the subject of the grant.

    Authentication Flow
    ===================

    The role of the token endpoint in the overall OAuth2 flow is described in
    https://tools.ietf.org/html/rfc6749#section-3.2 and illustrated in
    https://tools.ietf.org/html/rfc6749#section-1.2

    +--------+                               +---------------+
    |        |--(A)- Authorization Request ->|   Resource    |
    |        |                               |     Owner     |
    |        |<-(B)-- Authorization Grant ---|               |
    |        |                               +---------------+
    |        |
    |        |                               +---------------+
    |        |--(C)-- Authorization Grant -->| Authorization |
    | Client |                               |     Server    |
    |        |<-(D)----- Access Token -------|               |
    |        |                               +---------------+
    |        |
    |        |                               +---------------+
    |        |--(E)----- Access Token ------>|    Resource   |
    |        |                               |     Server    |
    |        |<-(F)--- Protected Resource ---|               |
    +--------+                               +---------------+

    (A) In our case, the 'Authorization Request' is superseded with the act
        of the already authenticated resource owner issuing a service key, and
        handing the private key to the client application to be authorized.

    (B) The client application then creates its own Authorization Grants on
        the behalf of the Resource Owner. These are signed JWTs with their
        claims tied to the service key.

    (C) The client application requests an access token by presenting its
        authorization grant to the token endpoint (this view).

    (D) If the grant passes validation, this token endpoint responds with
        a time limited access token tied to the service key.
        The token is stored in a storage on the PAS plugin, and tied to
        the service key.

    (E) The client application requests the protected resource and
        authenticates by presenting the access token.

    (F) The resource server validates the access token, and if valid,
        serves the protected resource.

        Validation of the access token is done in the PAS Plugin, which looks
        up the service_key tied to the access token (if found in storage),
        and then authenticates the client as the user who is the owner of
        the service key.

    This endpoint is concerned with steps (C) and (D), exchanging an
    authorization grant for an access token.

    Relevant Specifications
    =======================

    Authorization Grant
    -------------------

    The format of the authorization grant is not one of the four grant types
    defined in the core "OAuth 2.0 Authorization Framework", but instead an
    *extension grant* as described in

        RFC 6749 - 4.5. Extension Grants
        https://tools.ietf.org/html/rfc6749#section-4.5

    The specific extension grant type is the JWT grant as defined in

        RFC 7523 - JSON Web Token (JWT) Profile for [...] Authorization Grants
        https://tools.ietf.org/html/rfc7523

    Access Token
    ------------

    The format of the token returned by this endpoint is defined by

        RFC 6749 - 5.1. Successful Response
        https://tools.ietf.org/html/rfc6749#section-5

    The token type used is 'Bearer', as defined in

        RFC 6750 - The OAuth 2.0 Authorization Framework: Bearer Token Usage
        https://tools.ietf.org/html/rfc6750
    """

    def __call__(self):
        """Return an access token in exchange for a valid JWT grant.

        The client requests an access token by sending a POST request to this
        endpoint, with Content-Type 'application/x-www-form-urlencoded' and
        the form encoded body that contains the grant:

            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer"
            assertion:  JWT

        The JWT must be signed with RS256 (RSA Signature with SHA-256) and
        contain a claim set like this

            {"iss": <client_id>,
             "sub": <user_id>,
             "aud": "https://plone/@@oauth2-token",
             "iat": <current time>,
             "exp": <expiration time>}

        where <client_id> and <user_id> are properties of the service_key
        used to sign the JWT grant.

        If JWT grant is valid, the endpoint responds with a JSON response
        containing the access token:

            {"access_token": <token>,
             "expires_in": 3600,
             "token_type": "Bearer"}

        """
        try:
            self.only_allow_post()
            self.require_correct_grant_type()

            assertion = self.require_assertion()

            # According to yet UNVERIFIED claims in the JWT, this public key
            # should be used to check its signature
            service_key = self.get_potential_service_key(assertion)

            # Validate actual JWT assertion and signature using processor
            claimset = self.validate_jwt_grant(assertion, service_key)

            user_id = self.verified_subject(claimset, service_key)

        except ErrorResponse as exc:
            return self.send_error_response(exc)

        # All good, issue access token
        return self.issue_access_token(service_key, user_id)

    def only_allow_post(self):
        """Reject any requests that aren't POST.
        """
        # Clients MUST use POST, see
        # https://tools.ietf.org/html/rfc6749#section-3.2)
        if self.request.get('REQUEST_METHOD', 'GET').upper() != 'POST':
            raise InvalidRequest('POST only', status=405)

    def require_correct_grant_type(self):
        """Verify presence and appropriate kind of grant_type.
        """
        # We only support the JWT Bearer grant type as defined in
        # https://tools.ietf.org/html/rfc7523#section-2.1
        requested_grant_type = self.request.form.get('grant_type')

        if requested_grant_type is None:
            raise InvalidRequest("Missing 'grant_type'")

        if requested_grant_type != JWT_BEARER_GRANT_TYPE:
            raise InvalidRequest(
                'Only grant type %r is supported' % JWT_BEARER_GRANT_TYPE)

    def require_assertion(self):
        """Verify presence of an assertion and return it.
        """
        assertion = self.request.form.get('assertion')
        if not assertion:
            raise InvalidRequest("Missing 'assertion'")

        return assertion

    def get_potential_service_key(self, assertion):
        """Try to fetch the service key the JWT grant claims to be tied to.

        In order for that to happen, we need to decode the JWT first without
        verifying its signature, to extract the client_id that identifies the
        service_key that the JWT claims to be tied to.

        If that key can be found, it then can be used in a later step to
        actually verify the JWT's signature.
        """
        unverified_header = jwt.get_unverified_header(assertion)
        if unverified_header.get('alg') != u'RS256':
            raise InvalidRequest("Only RS256 signature algorithm is supported")

        unverified_claimset = jwt.decode(assertion, verify=False)

        client_id = unverified_claimset['iss']  # Issuer / Client-ID

        storage = CredentialStorage(self.plugin)
        service_key = storage.get_service_key_for_client_id(client_id)

        if service_key is None:
            raise InvalidGrant('No associated key found')

        return service_key

    def validate_jwt_grant(self, assertion, service_key):
        """Validate the actual claims of the JWT assertion and its signature.

        This is delegated to the JWTBearerGrantProcessor.
        """
        # Validate JWT according to RFC 7523 processing rules
        # (3. JWT Format and Processing Requirements)
        # https://tools.ietf.org/html/rfc7523#section-3
        processor = JWTBearerGrantProcessor(self.plugin.get_token_uri())
        try:
            return processor.verify(assertion, service_key)
        except (VerificationError, InvalidTokenError) as exc:
            raise InvalidGrant(str(exc))

    def verified_subject(self, claimset, service_key):
        """Verify the claim's subject and return it.

        If the subject does not match the userid of the service_key, the
        'Impersonate user' permission is required.
        """
        subject = claimset['sub']
        actor = service_key['user_id']
        if subject != actor:
            # Check if actor is allowed to impersonate
            uf = getToolByName(self.context, 'acl_users')
            user = uf.getUserById(actor)
            if not user:
                raise(InvalidGrant('Service key user not found.'))
            user = user.__of__(uf)

            old_security_manager = getSecurityManager()
            newSecurityManager(self.request, user)
            try:
                if not getSecurityManager().checkPermission(
                        ImpersonateUser, self.context):
                    raise InvalidGrant(
                        "JWT subject doesn't match user_id of service key.")
            finally:
                setSecurityManager(old_security_manager)

        return subject

    def issue_access_token(self, service_key, user_id):
        """Issue a time limited access token tied to service_key.

        Producing and storing the actual token is delegated to the PAS plugin.
        """
        # Token response according to RFC 6749 (5.1.  Successful Response)
        # https://tools.ietf.org/html/rfc6749#section-5

        # Token type is 'Bearer', as defined in RFC 6750
        # https://tools.ietf.org/html/rfc6750

        key_id = service_key['key_id']
        access_token = self.plugin.issue_access_token(key_id, user_id)
        token_data = {
            "access_token": access_token['token'],
            "expires_in": access_token['expires_in'],  # default: 3600
            "token_type": "Bearer",
        }
        return self.send_response(token_data)

    def send_error_response(self, exc):
        """Return error response for invalid grants or requests.
        """
        # Response format according to
        # https://tools.ietf.org/html/rfc6749#section-5.2
        # https://tools.ietf.org/html/rfc7523#section-3.1

        status = 400 if exc.status is None else exc.status
        self.request.response.setStatus(status)
        error = {'error': exc.error_type,
                 'error_description': exc.msg}
        return self.send_response(error)

    def send_response(self, response_data):
        """Return a JSON response with appropriate headers.
        """
        self.request.response.setHeader('Content-Type', 'application/json')

        # Set caching headers according to
        # https://tools.ietf.org/html/rfc6749#section-5.1
        self.request.response.setHeader('Cache-Control', 'no-store')
        self.request.response.setHeader('Pragma', 'no-cache')
        return json.dumps(response_data)

    @property
    def plugin(self):
        acl_users = api.portal.get().acl_users
        return acl_users['token_auth']
