from Crypto.Cipher import AES
import hashlib

aes_key = "A2CFF885901A5449E9C448BA5B948A8C4EE377152B3F1ACFA0148FB3A426DB72"  # Clave AES de 256 bits en formato hexadecimal

# Paso 1: Calculo del KCV usando SHA-256. Tomamos los primeros 3 bytes del hash.
key_bytes = bytes.fromhex(aes_key)
kcv_aes_256 = hashlib.sha256(key_bytes).digest()[:3]
print("KCV SHA-256:", kcv_aes_256.hex().upper())  # KCV SHA-256: DB7DF2

# Paso 2: Calculo del KCV usando cifrado AES en modo CBC con IV de ceros y texto plano de ceros.
iv = bytes(16)  # IV de 16 bytes (todos ceros)
plaintext = bytes(16)  # Texto plano de 16 bytes (todos ceros)
cipher = AES.new(key_bytes, AES.MODE_CBC, iv)  # Crear el objeto de cifrado AES en modo CBC
ciphertext = cipher.encrypt(plaintext)
kcv_aes_cbc = ciphertext[:3]
print("KCV AES-CBC:", kcv_aes_cbc.hex().upper())  # KCV AES-CBC: 5244DB
