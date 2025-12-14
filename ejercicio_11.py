from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


# Leemos la clave privada
with open('./assets/clave-rsa-oaep-priv.pem', 'rb') as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

# Leemos la clave pública
with open('./assets/clave-rsa-oaep-publ.pem', 'rb') as key_file:
    public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

cipher_text_hex = "b72e6fd48155f565dd2684df3ffa8746d649b11f0ed4637fc4c99d18283b32e1709b30c96b4a8a20d5dbc639e9d83a53681e6d96f76a0e4c279f0dffa76a329d04e3d3d4ad629793eb00cc76d10fc00475eb76bfbc1273303882609957c4c0ae2c4f5ba670a4126f2f14a9f4b6f41aa2edba01b4bd586624659fca82f5b4970186502de8624071be78ccef573d896b8eac86f5d43ca7b10b59be4acf8f8e0498a455da04f67d3f98b4cd907f27639f4b1df3c50e05d5bf63768088226e2a9177485c54f72407fdf358fe64479677d8296ad38c6f177ea7cb74927651cf24b01dee27895d4f05fb5c161957845cd1b5848ed64ed3b03722b21a526a6e447cb8ee"
cipher_text_original = bytes.fromhex(cipher_text_hex)

# Tarea 1: Descifrar el texto cifrado para recuperar la clave simétrica original
#          Descifrar con RSA-OAEP usando SHA-256
# fmt: off
symmetric_key = private_key.decrypt(
    cipher_text_original,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
# fmt: on

# Tarea 2: Volver a cifrar esa clave con el mismo algoritmo
# fmt: off
cipher_text_reencrypted = public_key.encrypt(
    symmetric_key,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
# fmt: on

# Tarea 3: Comparar ambos textos cifrados y explicar por qué son diferentes
print(f"Texto cifrado original: {cipher_text_original.hex()} \n")
print(f"Texto cifrado nuevo: {cipher_text_reencrypted.hex()} \n")
print(f"¿Son iguales? {cipher_text_original == cipher_text_reencrypted}")


# Explicación:
"""
Los textos cifrados son diferentes dado que RSA-OAEP incorpora aleatoriedad en el proceso de padding. 
Cada operación de cifrado genera un valor aleatorio único que se mezcla con el mensaje original, garantizando que incluso cifrando el mismo contenido con la misma clave pública, el resultado sea siempre diferente. 
Esta es una característica de seguridad fundamental que previene ataques de análisis de patrones.

Aún así el mensaje descifrado (la clave simétrica original) es el mismo en ambos casos.
"""
