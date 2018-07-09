from datetime import datetime
from datetime import timedelta
from ftw.tokenauth.oauth2.exceptions import FarFutureExp
from ftw.tokenauth.oauth2.exceptions import IatInFuture
from ftw.tokenauth.oauth2.exceptions import IatTooFarInPast
from ftw.tokenauth.oauth2.exceptions import IssuerMismatch
from ftw.tokenauth.oauth2.exceptions import MissingExpClaim
from ftw.tokenauth.oauth2.exceptions import MissingIatClaim
from ftw.tokenauth.oauth2.exceptions import NBFClaimNotSupported
from ftw.tokenauth.oauth2.exceptions import ScopesNotSupported
import jwt


class JWTBearerGrantProcessor(object):
    """Processes an JWT bearer authorization grant according to RFC 7523.

    See https://tools.ietf.org/html/rfc7523#section-3

    Also relevant:

      RFC 7521 - Assertion Framework for OAuth 2.0 [...] Authorization Grants
      https://tools.ietf.org/html/rfc7521#section-5.2
    """

    def __init__(self, token_uri):
        self.token_uri = token_uri

    def verify(self, assertion, service_key):
        verified_claimset = jwt.decode(
            assertion, service_key['public_key'], algorithms='RS256',
            audience=self.token_uri)

        if verified_claimset['iss'] != service_key['client_id']:
            raise IssuerMismatch(
                "JWT issuer doesn't match client_id of service key")

        exp = verified_claimset.get('exp')
        if not exp:
            raise MissingExpClaim("Missing 'exp' claim")

        exp = datetime.fromtimestamp(exp)

        # Should have been verified by PyJWT above
        assert exp >= datetime.now()

        if (exp - datetime.now()) > timedelta(days=1):
            # Unreasonably far in the future
            raise FarFutureExp(
                "JWT expiration is more than a day in the future")

        # Should have been verified by PyJWT above
        assert verified_claimset['aud'] == self.token_uri

        if 'nbf' in verified_claimset:
            raise NBFClaimNotSupported("The 'nbf' claim is not suppported")

        iat = verified_claimset.get('iat')
        if not iat:
            raise MissingIatClaim("Missing 'iat' claim")

        iat = datetime.fromtimestamp(iat)

        if (datetime.now() - iat) > timedelta(hours=1):
            raise IatTooFarInPast(
                "JWT was issued more than an hour in the past")

        allowed_clock_skew = timedelta(minutes=1)
        if (iat - datetime.now()) > allowed_clock_skew:
            raise IatInFuture("JWT issue time is in the future")

        if 'scope' in verified_claimset:
            raise ScopesNotSupported("Scopes are not supported yet")

        return verified_claimset
