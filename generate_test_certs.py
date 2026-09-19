"""
Generates local TLS test servers with different crypto strengths, so you can
reproduce the exact demo screenshot (weak vs strong crypto) on your own machine
without depending on real internet hosts.

Usage:
    python3 generate_test_certs.py
    (then, in another terminal or after this prints "servers running"):
    python3 ecdat_scanner.py --host 127.0.0.1:8443   # weak/legacy
    python3 ecdat_scanner.py --host 127.0.0.1:8444   # strong
    python3 ecdat_scanner.py --host 127.0.0.1:8445   # medium
"""
import ssl, socket, threading, time, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def make_cert(cn, key_size, expiry_days):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=expiry_days))
            .sign(key, hashes.SHA256()))
    with open(f"{cn}_key.pem", "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    with open(f"{cn}_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def start_server(cn, port, key_size, expiry_days, min_v, max_v):
    make_cert(cn, key_size, expiry_days)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
    ctx.minimum_version = min_v
    ctx.maximum_version = max_v
    ctx.load_cert_chain(f'{cn}_cert.pem', f'{cn}_key.pem')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(5)

    def serve():
        while True:
            try:
                conn, addr = sock.accept()
                try:
                    with ctx.wrap_socket(conn, server_side=True) as tls_conn:
                        tls_conn.recv(1024)
                except Exception:
                    pass
                finally:
                    conn.close()
            except Exception:
                break

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    print(f"[{cn}] listening on 127.0.0.1:{port}  (RSA-{key_size}, expires in {expiry_days} days)")


if __name__ == "__main__":
    start_server("legacy-portal.internal", 8443, 1024, 8, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_2)
    start_server("auth-service.internal", 8445, 2048, 200, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)
    start_server("api-gateway.internal", 8444, 3072, 400, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)

    print("\nAll 3 test servers running. Keep this script running, then in another")
    print("terminal run:\n")
    print("  python3 ecdat_scanner.py --host 127.0.0.1:8443 --out weak_test.json")
    print("  python3 ecdat_scanner.py --host 127.0.0.1:8444 --out strong_test.json")
    print("  python3 ecdat_scanner.py --host 127.0.0.1:8445 --out medium_test.json")
    print("\nOr scan all three by adding to hosts.txt:")
    print("  127.0.0.1:8443\n  127.0.0.1:8444\n  127.0.0.1:8445\n")
    print("Press Ctrl+C to stop the servers.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")
