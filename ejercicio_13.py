from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ed25519
from cryptography.hazmat.backends import default_backend

message = "El equipo está preparado para seguir con el proceso, necesitaremos más recursos."
message_bytes = message.encode('utf-8')

# Tarea 1: Firmar el mensaje con RSA PKCS#1 v1.5
with open("./assets/clave-rsa-oaep-priv.pem", "rb") as f:
    private_rsa_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

# Firmar el mensaje usando PKCS#1 v1.5 con SHA-256
signature = private_rsa_key.sign(message_bytes, padding.PKCS1v15(), hashes.SHA256())

# Respuesta a la pregunta "¿Cuál es el valor de la firma en hexadecimal?" del ejercicio
signature_rsa_hex = signature.hex()
print(f"Firma RSA PKCS#1 v1.5 en hexadecimal: {signature_rsa_hex}\n")

# Tarea 2: Firmar con Ed25519
with open("./assets/ed25519-priv", "rb") as f:
    key_data = f.read()[:32]  # Cogemos solo los primeros 32 bytes
    private_ed25519_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_data)


signature_ed25519 = private_ed25519_key.sign(message_bytes)
signature_ed25519_hex = signature_ed25519.hex()
print(f"Firma Ed25519 en hexadecimal: {signature_ed25519_hex}")
