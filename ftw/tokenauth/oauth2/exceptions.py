class VerificationError(Exception):
    """Base class for all errors during JWT authorization grant verification.
    """


class IssuerMismatch(VerificationError):
    """JWT 'iss' claim doesn't match client_id of service key.
    """


class MissingExpClaim(VerificationError):
    """JWT is missing an 'exp' claim.
    """


class MissingIatClaim(VerificationError):
    """JWT is missing an 'iat' claim.
    """


class FarFutureExp(VerificationError):
    """JWT expiration is too far in the future.
    """


class IatTooFarInPast(VerificationError):
    """JWT was issued too far in the the past.
    """


class IatInFuture(VerificationError):
    """JWT issue time is in the future.
    """


class NBFClaimNotSupported(VerificationError):
    """JWT contains an 'nbf' claim, which is not suppported.
    """


class ScopesNotSupported(VerificationError):
    """JWT contains a 'scope' claim, which is not suppported.
    """
