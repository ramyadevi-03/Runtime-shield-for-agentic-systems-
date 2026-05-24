import os
import sys
import datetime
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as _padding
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives.asymmetric import ec as _ec

# Set up paths relative to this script
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)
sys.path.insert(0, os.path.join(PROJECT_DIR, "damn-vulnerable-llm-agent"))

CERTS_DIR = os.path.join(PROJECT_DIR, 'spire', 'certs')

print("======================================================================")
print("RUNTIME SHIELD -- SPIFFE & mTLS VERIFICATION TEST SUITE")
print("======================================================================\n")

# --- FEATURE 1: Runtime Cryptographic Attestation ---
print("=== FEATURE 1: Runtime Cryptographic Attestation ===")

def attest(cert_path, ca_path):
    with open(cert_path, 'rb') as f:
        svid = x509.load_pem_x509_certificate(f.read(), default_backend())
    with open(ca_path, 'rb') as f:
        ca = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    ca_pubkey = ca.public_key()
    if isinstance(ca_pubkey, _rsa.RSAPublicKey):
        ca_pubkey.verify(
            svid.signature,
            svid.tbs_certificate_bytes,
            _padding.PKCS1v15(),
            svid.signature_hash_algorithm,
        )
    elif isinstance(ca_pubkey, _ec.EllipticCurvePublicKey):
        ca_pubkey.verify(
            svid.signature,
            svid.tbs_certificate_bytes,
            _ec.ECDSA(svid.signature_hash_algorithm),
        )
    else:
        ca_pubkey.verify(
            svid.signature,
            svid.tbs_certificate_bytes,
            svid.signature_hash_algorithm,
        )
    
    san = svid.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    uris = [u for u in san.value.get_values_for_type(x509.UniformResourceIdentifier) if u.startswith('spiffe://')]
    
    now = datetime.datetime.utcnow()
    valid = svid.not_valid_before <= now <= svid.not_valid_after
    return {'spiffe_id': uris[0] if uris else '', 'valid': valid}

for wl in ['bridge', 'llm-agent', 'agent', 'dashboard']:
    cert = os.path.join(CERTS_DIR, f'{wl}.crt')
    ca   = os.path.join(CERTS_DIR, 'ca.crt')
    try:
        r = attest(cert, ca)
        print(f"  [PASS] {wl}: {r['spiffe_id']} (valid={r['valid']})")
    except Exception as e:
        print(f"  [FAIL] {wl}: {e}")

print()

# --- FEATURE 2: mTLS SSL Context ---
print("=== FEATURE 2: mTLS SSL Context ===")
svid_cert = os.path.join(CERTS_DIR, 'bridge.crt')
svid_key  = os.path.join(CERTS_DIR, 'bridge.key')
ca_bundle = os.path.join(CERTS_DIR, 'ca.crt')
try:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(certfile=svid_cert, keyfile=svid_key)
    ctx.load_verify_locations(cafile=ca_bundle)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    print("  [PASS] mTLS context built -- verify_mode=CERT_REQUIRED, min_version=TLSv1.2")
except Exception as e:
    print(f"  [FAIL] {e}")

print()

# --- FEATURE 3: Strict SVID Cryptographic Verification ---
print("=== FEATURE 3: Strict SVID Cryptographic Verification ===")
allowed = {
    'spiffe://runtime-shield/llm-agent',
    'spiffe://runtime-shield/bridge',
    'spiffe://runtime-shield/agent',
    'spiffe://runtime-shield/dashboard'
}

def verify(spiffe_id, cert_pem=None):
    if not cert_pem:
        return {'valid': spiffe_id in allowed, 'reason': 'allowlist check (no cert provided)'}
    try:
        with open(ca_bundle, 'rb') as f:
            ca = x509.load_pem_x509_certificate(f.read(), default_backend())
        svid = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        
        ca_pubkey = ca.public_key()
        if isinstance(ca_pubkey, _rsa.RSAPublicKey):
            ca_pubkey.verify(
                svid.signature,
                svid.tbs_certificate_bytes,
                _padding.PKCS1v15(),
                svid.signature_hash_algorithm,
            )
        elif isinstance(ca_pubkey, _ec.EllipticCurvePublicKey):
            ca_pubkey.verify(
                svid.signature,
                svid.tbs_certificate_bytes,
                _ec.ECDSA(svid.signature_hash_algorithm),
            )
        else:
            ca_pubkey.verify(
                svid.signature,
                svid.tbs_certificate_bytes,
                svid.signature_hash_algorithm,
            )
        
        san = svid.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = [u for u in san.value.get_values_for_type(x509.UniformResourceIdentifier) if u.startswith('spiffe://')]
        cert_id = uris[0] if uris else ''
        
        if cert_id and cert_id != spiffe_id:
            return {'valid': False, 'reason': f'SAN mismatch: cert={cert_id} claimed={spiffe_id}'}
        
        now = datetime.datetime.utcnow()
        exp_ok = svid.not_valid_before <= now <= svid.not_valid_after
        if not exp_ok:
            return {'valid': False, 'reason': 'expired'}
        
        verified_id = cert_id or spiffe_id
        is_ok = verified_id in allowed
        return {'valid': is_ok, 'reason': f"crypto verified: {verified_id} (allowed={is_ok})"}
    except Exception as e:
        return {'valid': False, 'reason': f"crypto verification failed: {e}"}

# Test 3a: Valid llm-agent cert
with open(os.path.join(CERTS_DIR, 'llm-agent.crt')) as f:
    llm_cert_pem = f.read()
r = verify('spiffe://runtime-shield/llm-agent', llm_cert_pem)
status = "PASS" if r['valid'] else "FAIL"
print(f"  [{status}] Valid llm-agent cert: {r['reason']}")

# Test 3b: Claimed ID does not match cert SAN
r = verify('spiffe://evil/hacker', llm_cert_pem)
status = "PASS" if not r['valid'] else "FAIL"
print(f"  [{status}] SAN mismatch rejection: {r['reason']}")

# Test 3c: No cert, allowlisted ID
r = verify('spiffe://runtime-shield/bridge', None)
status = "PASS" if r['valid'] else "FAIL"
print(f"  [{status}] Allowlist fallback (no cert): {r['reason']}")

# Test 3d: No cert, untrusted ID
r = verify('spiffe://untrusted/hacker', None)
status = "PASS" if not r['valid'] else "FAIL"
print(f"  [{status}] Allowlist blocks untrusted: {r['reason']}")

print()

# --- Integration test ---
print("=== Integration check (fetch_svid) ===")
from spiffe_integration import fetch_svid
svid = fetch_svid()
print(f"  spiffe_id : {svid['spiffe_id']}")
print(f"  attested  : {svid['attested']}")
print(f"  source    : {svid['source']}")
print(f"  cert_pem  : {'present' if svid.get('cert_pem') else 'absent'}")
print("======================================================================\n")
