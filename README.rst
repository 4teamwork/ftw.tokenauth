ftw.tokenauth
=============

PAS plugin that facilitates **machine-to-machine authentication** by
implementing a two legged OAuth2 flow using service keys and short-lived
access tokens.

Installation
============

- Add ``ftw.tokenauth`` to your buildout configuration or as a dependency
  of your policy package:

  .. code:: ini
  
      [instance]
      eggs +=
          ftw.tokenauth

- Install the generic setup profile of ``ftw.tokenauth``.


Configuration
=============

For a user to be allowed to issue (or otherwise manage) service keys, they
require the ``ftw.tokenauth: Manage own Service Keys`` permission. So
integration packages need to assign this permission to roles that should be
allowed to use service keys.


Authentication flow
===================

The authentication flow involves four steps:

1. A logged in service user issues a service key in Plone, and stores the
   private key in a safe location accessible to the client application.

2. The client application uses the private key to create and sign a JWT
   authorization grant.

3. The client application exchanges the JWT authorization grant for a
   short-lived access token at the ``@@oauth2-token`` endpoint.

4. The client then uses this access token to authenticate requests to
   protected resources.


Assuming the client is in possession of a service key, the flow looks like this:

  .. code::

    +--------+                                     +---------------+
    |        |-- Create and sign JWT               |               |
    |        |                                     |               |
    |        |                                     |               |
    |        |                                     |               |
    |        |-- Use JWT to request token -------->|               |
    |        |                                     |               |
    |        |                                     |               |
    | Client |                                     |     Plone     |
    |        |<----------------- Token response ---|               |
    |        |                                     |               |
    |        |                                     |               |
    |        |                                     |               |
    |        |-- Use token to authenticate ------->|               |
    |        |                                     |               |
    |        |                                     |               |
    +--------+                                     +---------------+

Usage
=====

In order to set up machine-to-machine authentication for a client, the
following steps need to be performed:

1. Issue Service Key
--------------------

A user that has already authenticated to Plone using regular means, and has
the ``ftw.tokenauth: Manage own Service Keys`` permission, can issue service
keys for their account via the ``@@manage-service-keys`` view
(``Manage Service Keys`` action in personal tools menu).

They need to issue a service key that is then displayed **exactly once** for
download, and store the private key in a safe location accessible to the
client that will use it.

`IP range restrictions`_ may also be defined when issuing a key.

TODO: Document Key revocation.

2. Create and sign JWT authorization grant using service key
------------------------------------------------------------

In order to request an access token, the client application then uses the
private service key to create and sign a JWT.

The JWT needs to contain the following claims:

==== ========================================================================
Name Description
==== ========================================================================
iss  Issuer - must be ``client_id`` from service key
aud  Audience - must be ``token_uri`` from service key
sub  Subject - must be ``user_id`` from service key
iat  The time the assertion was issued, specified as seconds since
     00:00:00 UTC, January 1, 1970.
exp  The expiration time of the assertion, specified as seconds since
     00:00:00 UTC, January 1, 1970. This value has a maximum of 1 hour after
     the issued time.
==== ========================================================================

The JWT then needs to be signed with the private key. The only supported
signature algorithm is ``RS256``.


Python Example:

  .. code:: python

    import json
    import jwt
    import time

    # Load saved key from filesystem
    service_key = json.load(open('my_saved_key.json', 'rb'))

    private_key = service_key['private_key'].encode('utf-8')

    claim_set = {
        "iss": service_key['client_id'],
        "sub": service_key['user_id'],
        "aud": service_key['token_uri'],
        "iat": int(time.time()),
        "exp": int(time.time() + (60 * 60)),
    }
    grant = jwt.encode(claim_set, private_key, algorithm='RS256')


3. Token request (exchange JWT grant for an access token)
---------------------------------------------------------

The client then makes a token request to the ``token_uri`` with the JWT grant
it created.

This request needs to be a ``POST`` request with
``Content-Type: application/x-www-form-urlencoded`` and a request body that
contains the form encoded parameters.

Two parameters are required:

=========== =================================================================
Name        Description
=========== =================================================================
grant_type  Must always be ``urn:ietf:params:oauth:grant-type:jwt-bearer``
assertion   The JWT authorization grant
=========== =================================================================

The token endpoint will then respond with a token response containing the
access token:

  .. code:: python

    {"access_token": <token>,
     "expires_in": 3600,
     "token_type": "Bearer"}

The response will be of ``Content-Type: application/json`` and contain a JSON
encoded body.

Python Example:

  .. code:: python

    import requests

    GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'

    payload = {'grant_type': GRANT_TYPE, 'assertion': grant}
    response = requests.post(service_key['token_uri'], data=payload)
    token = response.json()['access_token']

TODO: Document error responses for token requests


4. Use access token to authenticate requests
--------------------------------------------

The client can then use the access token to authenticate requests. The token
needs to be sent in the HTTP ``Authorization`` header as a ``Bearer`` token.

Once the token expires, the client must create a JWT authorization grant again,
and request a new access token.

Python Example:

  .. code:: python

    with requests.Session() as session:
        session.headers.update({'Authorization': 'Bearer %s' % token})
        response = session.get('http://localhost:8080/Plone/')
        # ...

TODO: Document error responses for invalid tokens


Advanced use
============

This section covers some more advanced settings and functionality of
``ftw.tokenauth``.

IP range restrictions
---------------------

When issuing a key, IP range restrictions may be defined that limit from what
source IP address access tokens tied to this key may be used.

Changes to IP range restrictions for a given key are effective immediately,
and also affect already issued tokens tied to this key.

IP ranges may be specified as a single IP address or as a network in
`CIDR notation <https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation>`_
using the slash-suffix.

Multiple ranges may be provided in comma-separated form.

Examples of valid IP range specifications:

- ``192.168.1.1``
- ``192.168.0.0/16``
- ``192.168.1.1, 10.0.0.0/8``

Authentication attempts from an unauthorized source IP address are logged
server side, but not indicated to the client in any particular way -
authentication is simply not performed.

Usage logs
----------

In the "Manage Service Keys" view, the last use of a key to issue access
tokens is listed in the "Last Used" column. Clicking on this timestamp
displays a detailed log of most recent uses of the key.

By default, these logs list the uses of the key in the last 7 days (the
usage log retention period can be configured as a property on the PAS Plugin
via the ZMI).

The log entry with the most recent use of a key is always retained, while
the other log entries are cleaned out if they're expired (cleanup happens
whenever a any new access token is issued).

The logs don't show use of access tokens to authenticate, but instead they
show every instance where JWT authentication grants signed with this key
were used to obtain a new access token.


Links
=====

- Github: https://github.com/4teamwork/ftw.tokenauth
- Issues: https://github.com/4teamwork/ftw.tokenauth/issues
- Continuous integration: https://jenkins.4teamwork.ch/search?q=ftw.tokenauth


Copyright
=========

This package is copyright by `4teamwork <http://www.4teamwork.ch/>`_.

``ftw.tokenauth`` is licensed under GNU General Public License, version 2.
