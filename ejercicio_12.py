from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import binascii
import base64

key_hex = "E2CFF885901B3449E9C448BA5B948A8C4EE322152B3F1ACFA0148FB3A426DB74"
nonce_b64 = "9Yccn/f5nJJhAt2S"
plaintext = "He descubierto el error y no volveré a hacerlo mal"

key = binascii.unhexlify(key_hex)
nonce = base64.b64decode(nonce_b64)
plaintext_bytes = plaintext.encode('utf-8')

# Ciframos el mensaje
aesgcm_encryptor = AESGCM(key)
ciphertext_with_tag = aesgcm_encryptor.encrypt(nonce, plaintext_bytes, None)

# Convertimos a hexadecimal
ciphertext_hex = binascii.hexlify(ciphertext_with_tag).decode('utf-8')
print(f"Texto cifrado en hexadecimal: {ciphertext_hex}\n")

# Convertimos a base64
ciphertext_b64 = base64.b64encode(ciphertext_with_tag).decode('utf-8')
print(f"Texto cifrado en base64: {ciphertext_b64}")


"""
1. [GRAVE] Reutilización del Nonce en AES/GCM
> En el enunciado se indica:
> “Nuestro sistema usa los siguientes datos en cada comunicación con el tercero”

AES/GCM requiere obligatoriamente que el nonce (IV):
- Sea único para cada cifrado realizado con la misma clave
- Nunca se reutilice

Consecuencias de reutilizar el nonce:
- Un atacante puede recuperar información del texto plano
- Puede crear mensajes válidos
- Se pierde tanto confidencialidad como autenticidad

2. [MODERADO] Longitud y formato incorrecto del nonce
> El nonce proporcionado es:
> 9Yccn/f5nJJhAt2S

El nonce se recomienda que tenga una longitud de 12 bytes (96 bits) para AES/GCM.
Si el nonce no tiene la longitud adecuada, puede afectar la seguridad del cifrado.

3. [GRAVE] Falta de mención del Authentication Tag
> No se menciona el Authentication Tag en el enunciado.
El Authentication Tag es crucial en AES/GCM para garantizar la integridad y autenticidad del mensaje.
Sin el tag, no se puede verificar si el mensaje ha sido alterado durante la transmisión.
"""
