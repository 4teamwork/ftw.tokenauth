from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime
import hashlib
import os


class KeyGenerator(object):
    """Create an RSA key pair (public/private keys).
    """

    def generate_rsa_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

        fingerprint = hashlib.sha1(public_pem).hexdigest()

        pair = {}
        pair['public_key'] = public_pem
        pair['private_key'] = private_pem
        pair['fingerprint'] = fingerprint
        pair['issued'] = datetime.now()
        return pair


def create_client_id():
    """Create an OAuth2 client ID (opaque string).
    """
    return os.urandom(16).encode('hex')


def create_service_key_pair(user_id, title, token_uri):
    """Create a service key pair (public and private keys) with metadata.
    """
    keypair = KeyGenerator().generate_rsa_key_pair()

    client_id = create_client_id()
    service_key = {
        'key_id': keypair['fingerprint'],
        'client_id': client_id,
        'issued': keypair['issued'],
        'user_id': user_id,
        'public_key': keypair['public_key'],
        'title': title,
        'token_uri': token_uri,
    }
    return keypair['private_key'], service_key
