import ssl
import socket
import contextlib
import warnings
from typing import Any, Dict, List
from pydantic import BaseModel
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


class Certificate(BaseModel):
    version: str
    serial: int
    validity: Dict[str, str]
    issuer: Dict[str, str | bytes]
    fingerprints: Dict[str, bytes]
    extensions: Dict[str, Any]
    ciphers: List[str]


class SSLInspect:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def certificate(self):
        cert_model = Certificate
        pem_data = bytes(ssl.get_server_certificate((self.host, self.port)), "utf-8")
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())

        cert_model.version = cert.version.name
        cert_model.serial = cert.serial_number
        cert_model.validity = {
            "not_valid_before": cert.not_valid_before.__str__(),
            "not_valid_after": cert.not_valid_after.__str__(),
        }
        cert_model.issuer = {attr.oid._name: attr.value for attr in cert.issuer}
        cert_model.fingerprints = {
            "SHA256": cert.fingerprint(hashes.SHA256()),
            "SHA1": cert.fingerprint(hashes.SHA1()),
        }
        cert_model.extensions = SSLInspect.__extensions(cert)
        cert_model.ciphers = self.supported_ciphers()

        return cert_model.__dict__

    @staticmethod
    def __extensions(cert: x509.Certificate):
        ext_dict = {}
        for ext in cert.extensions:
            ext_name = ext.oid._name if ext.oid._name else str(ext.oid)
            ext_dict[ext_name] = {"critical": ext.critical, "value": ext.value}
        return ext_dict

    def supported_ciphers(self):
        available_ciphers = ssl.create_default_context().get_ciphers()
        supported_ciphers = []

        for cipher in available_ciphers:
            cipher_name = cipher["name"]
            with contextlib.suppress(Exception):
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.set_ciphers(cipher_name)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((self.host, self.port), timeout=2) as sock:
                    with context.wrap_socket(sock, server_hostname=self.host):
                        supported_ciphers.append(cipher_name)

        return supported_ciphers
