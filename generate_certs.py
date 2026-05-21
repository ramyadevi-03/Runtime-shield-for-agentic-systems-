from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import os

def generate_certs(output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Generate CA Key
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # 2. Generate CA Certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Runtime Shield SPIRE CA"),
    ])
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(ca_key, hashes.SHA256())

    # 3. Generate Agent Key
    agent_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # 4. Generate Agent Certificate (signed by CA)
    agent_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"spire-agent"),
    ])
    agent_cert = x509.CertificateBuilder().subject_name(
        agent_subject
    ).issuer_name(
        issuer
    ).public_key(
        agent_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    ).sign(ca_key, hashes.SHA256())

    # Write files
    def write_key(key, filename):
        with open(os.path.join(output_dir, filename), "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

    def write_cert(cert, filename):
        with open(os.path.join(output_dir, filename), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    write_key(ca_key, "ca.key")
    write_cert(ca_cert, "ca.crt")
    write_key(agent_key, "agent.key")
    write_cert(agent_cert, "agent.crt")
    
    print(f"✅ Certificates generated in {output_dir}")

if __name__ == "__main__":
    # Fixed path for the active workspace
    generate_certs(r"c:\Users\Lenovo\Desktop\Runtime-shield- login\Runtime-shield-for-agentic-systems\spire\certs")
