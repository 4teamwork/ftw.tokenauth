from ftw.builder import Builder
from ftw.builder import create
from ftw.tokenauth.oauth2.exceptions import FarFutureExp
from ftw.tokenauth.oauth2.exceptions import IatInFuture
from ftw.tokenauth.oauth2.exceptions import IatTooFarInPast
from ftw.tokenauth.oauth2.exceptions import IssuerMismatch
from ftw.tokenauth.oauth2.exceptions import MissingExpClaim
from ftw.tokenauth.oauth2.exceptions import MissingIatClaim
from ftw.tokenauth.oauth2.exceptions import NBFClaimNotSupported
from ftw.tokenauth.oauth2.exceptions import ScopesNotSupported
from ftw.tokenauth.oauth2.exceptions import SubjectMismatch
from ftw.tokenauth.oauth2.jwt_grants import JWTBearerGrantProcessor
from ftw.tokenauth.testing import FTW_TOKENAUTH_UNIT_TESTING
from ftw.tokenauth.testing.layers import DEFAULT_TESTING_TOKEN_URI
from jwt.exceptions import ExpiredSignatureError
from jwt.exceptions import InvalidAudienceError
import time
import unittest


class TestJWTGrantVerification(unittest.TestCase):

    layer = FTW_TOKENAUTH_UNIT_TESTING

    def setUp(self):
        self.token_uri = DEFAULT_TESTING_TOKEN_URI
        self.processor = JWTBearerGrantProcessor(self.token_uri)

    def test_jwt_issuer_must_match_service_key_client_id(self):
        # https://tools.ietf.org/html/rfc7521#section-5.2

        # The assertion MUST contain an Issuer. The Issuer identifies the
        # entity that issued the assertion as recognized by the
        # authorization server.  If an assertion is self-issued, the Issuer
        # MUST be the value of the client's "client_id".

        private_key, service_key = create(
            Builder('keypair')
            .having(client_id='actual-client-id'))

        invalid_grant_token = create(
            Builder('jwt_grant')
            .from_keypair((private_key, service_key))
            .having(iss='bogus-client-id'))

        with self.assertRaises(IssuerMismatch):
            self.processor.verify(invalid_grant_token, service_key)

    def test_jwt_subject_must_match_service_key_user_id(self):
        # https://tools.ietf.org/html/rfc7521#section-5.2

        # The assertion MUST contain a Subject. The Subject typically
        # identifies an authorized accessor for which the access token is
        # being requested (i.e., the resource owner or an authorized
        # delegate)

        private_key, service_key = create(
            Builder('keypair')
            .having(user_id='actual-user-id'))

        invalid_grant_token = create(
            Builder('jwt_grant')
            .from_keypair((private_key, service_key))
            .having(sub='bogus-user-id'))

        with self.assertRaises(SubjectMismatch):
            self.processor.verify(invalid_grant_token, service_key)

    def test_jwt_must_contain_exp_claim(self):
        # https://tools.ietf.org/html/rfc7521#section-5.2

        # The assertion MUST contain an Expires At entity that limits the
        # time window during which the assertion can be used.
        private_key, service_key = create(Builder('keypair'))

        invalid_grant_token = create(
            Builder('jwt_grant')
            .from_keypair((private_key, service_key))
            .without(['exp']))

        with self.assertRaises(MissingExpClaim):
            self.processor.verify(invalid_grant_token, service_key)

    def test_jwt_must_not_be_expired(self):
        # https://tools.ietf.org/html/rfc7521#section-5.2

        # The authorization server MUST reject assertions that have expired
        # (subject to allowable clock skew between systems).

        private_key, service_key = create(Builder('keypair'))

        invalid_grant_token = create(
            Builder('jwt_grant')
            .from_keypair((private_key, service_key))
            # Expired one minute ago
            .having(exp=int(time.time()) - 60))

        with self.assertRaises(ExpiredSignatureError):
            self.processor.verify(invalid_grant_token, service_key)

    def test_jwt_exp_most_not_be_far_in_future(self):
        # https://tools.ietf.org/html/rfc7521#section-5.2

        # Note that the authorization server may reject assertions with an
        # Expires At attribute value that is unreasonably far in the future.
        private_key, service_key = create(Builder('keypair'))

        invalid_grant_token = create(
            Builder('jwt_grant')
            .from_keypair((private_key, service_key))
            # Three days in the future
            .having(exp=int(time.time()) + (60 * 60 * 72)))

        with self.assertRaises(FarFutureExp):
            self.processor.verify(invalid_grant_token, service_key)

    def test_jwt_audience_must_match_token_uri_of_site(self):
        # https://tools.ietf.org/html/rfc7521#section-5.2

        # The assertion MUST contain an Audience that identifies the
        # authorization server as the intended audience. The authorization
        # server MUST reject any assertion that does not contain its own
        # identity as the intended audience.

        private_key, service_key = create(Builder('keypair'))

        invalid_grant_token = create(
            Builder('jwt_grant')
            .from_keypair((private_key, service_key))
            .having(aud='http://bogus.example.org'))

        with self.assertRaises(InvalidAudienceError):
            self.processor.verify(invalid_grant_token, service_key)

    def test_jwt_must_not_contain_nbf_claim(self):
        private_key, service_key = create(Builder('keypair'))

        invalid_grant_token = create(
            Builder('jwt_grant')
            .from_keypair((private_key, service_key))
            .having(nbf=int(time.time())))

        with self.assertRaises(NBFClaimNotSupported):
            self.processor.verify(invalid_grant_token, service_key)

    def test_jwt_must_contain_iat_claim(self):
        # https://tools.ietf.org/html/rfc7521#section-5.2

        # The assertion MAY contain an Issued At entity containing the UTC
        # time at which the assertion was issued.

        private_key, service_key = create(Builder('keypair'))

        invalid_grant_token = create(
            Builder('jwt_grant')
            .from_keypair((private_key, service_key))
            .without(['iat']))

        with self.assertRaises(MissingIatClaim):
            self.processor.verify(invalid_grant_token, service_key)

    def test_jwt_iat_must_not_be_too_far_in_past(self):
        private_key, service_key = create(Builder('keypair'))

        invalid_grant_token = create(
            Builder('jwt_grant')
            .from_keypair((private_key, service_key))
            # Two hours in the past
            .having(iat=int(time.time()) - (60 * 60 * 2)))

        with self.assertRaises(IatTooFarInPast):
            self.processor.verify(invalid_grant_token, service_key)

    def test_jwt_iat_must_not_be_in_future(self):
        private_key, service_key = create(Builder('keypair'))

        invalid_grant_token = create(
            Builder('jwt_grant')
            .from_keypair((private_key, service_key))
            # One hour in the future
            .having(iat=int(time.time()) + (60 * 60)))

        with self.assertRaises(IatInFuture):
            self.processor.verify(invalid_grant_token, service_key)

    def test_jwt_scope_claims_are_rejected(self):
        private_key, service_key = create(Builder('keypair'))

        invalid_grant_token = create(
            Builder('jwt_grant')
            .from_keypair((private_key, service_key))
            .having(scope='some.scope'))

        with self.assertRaises(ScopesNotSupported):
            self.processor.verify(invalid_grant_token, service_key)

    def test_jwt_iat_future_check_allows_for_some_clock_skew(self):
        private_key, service_key = create(Builder('keypair'))

        valid_grant_token = create(
            Builder('jwt_grant')
            .from_keypair((private_key, service_key))
            # 30s in future - should fall within allowed margin for clock skew
            .having(iat=int(time.time()) + 30))

        self.assertTrue(self.processor.verify(valid_grant_token, service_key))

    def test_valid_grant_token_passes_verification(self):
        private_key, service_key = create(Builder('keypair'))

        valid_grant_token = create(
            Builder('jwt_grant')
            .from_keypair((private_key, service_key)))

        self.assertTrue(self.processor.verify(valid_grant_token, service_key))
