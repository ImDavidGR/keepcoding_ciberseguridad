import jks
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64


def leer_clave_keystore(keystore_path, keystore_password, tag):
    try:
        keystore = jks.KeyStore.load(keystore_path, keystore_password)

        # Buscar la entrada con el tag especificado
        if tag in keystore.entries:
            entry = keystore.entries[tag]

            # Dependiendo del tipo de entrada, extraer la clave
            if isinstance(entry, jks.SecretKeyEntry):
                return {"success": True, "key": entry.key, "error": None}

            elif isinstance(entry, jks.PrivateKeyEntry):
                return {"success": False, "key": None, "error": "La entrada es una clave privada, no una clave secreta."}

            else:
                return {"success": False, "key": None, "error": "Tipo de entrada no soportado."}
        else:
            return {"success": False, "key": None, "error": "El tag especificado no existe en el keystore."}

    except jks.KeystoreSignatureException:
        return {"success": False, "key": None, "error": "Contraseña del keystore incorrecta."}
    except jks.KeystoreException as ke:
        return {"success": False, "key": None, "error": f"Error del keystore: {str(ke)}"}
    except Exception as e:
        return {"success": False, "key": None, "error": str(e)}


def descifrar_aes_cbc(clave, iv, datos_cifrados, padding_mode):
    try:
        cipher = AES.new(clave, AES.MODE_CBC, iv)
        datos_descifrados_con_padding = cipher.decrypt(datos_cifrados)

        # Deshacer el padding según el modo
        if padding_mode == "pkcs7":
            datos_descifrados = unpad(datos_descifrados_con_padding, AES.block_size, style="pkcs7")
        elif padding_mode == "x923":
            datos_descifrados = unpad(datos_descifrados_con_padding, AES.block_size, style="x923")
        else:
            raise ValueError(f"Modo de padding no soportado: {padding_mode}")

        return datos_descifrados, datos_descifrados_con_padding

    except Exception as e:
        raise Exception(f"Error en descifrado con padding {padding_mode}: {e}")


def analizar_padding(datos_con_padding):
    """Analiza el padding añadido al final de los datos"""
    ultimo_byte = datos_con_padding[-1]
    padding_length = ultimo_byte
    return padding_length


keystore_path = "./assets/KeyStorePracticas"
keystore_password = "123456"
tag = "cifrado-sim-aes-256"

key_response = leer_clave_keystore(keystore_path, keystore_password, tag)
if key_response["success"]:
    key = key_response["key"]
else:
    raise Exception(key_response["error"])

texto_cifrado_b64 = "TQ9SOMKc6aFS9SlxhfK9wT18UXpPCd505Xf5J/5nLI7Of/o0QKIWXg3nu1RRz4QWElezdrLAD5LO4USt3aB/i50nvvJbBiG+le1ZhpR84oI="
datos_cifrados = base64.b64decode(texto_cifrado_b64)

iv = b"\x00" * 16

print("=" * 60)
print("DESCIFRADO DEL TEXTO CIFRADO CON AES-256 EN MODO CBC CON PADDING PKCS7")
print("=" * 60)
texto_descifrado, texto_con_padding = descifrar_aes_cbc(key, iv, datos_cifrados, "pkcs7")
print(texto_descifrado.decode("utf-8"), "\n")
# RESPUESTA: Esto es un cifrado en bloque típico. Recuerda, vas por el buen camino. Ánimo.

print("=" * 60)
print("DESCIFRADO DEL TEXTO CIFRADO CON AES-256 EN MODO CBC CON PADDING X923")
print("=" * 60)
texto_descifrado_x923, texto_con_padding_x923 = descifrar_aes_cbc(key, iv, datos_cifrados, "x923")
print(texto_descifrado_x923.decode("utf-8"))

print("=" * 60)
print("ANÁLISIS DE PADDING EN EL DESCIFRADO CON PKCS7")
print("=" * 60)
padding_analizado = analizar_padding(texto_con_padding)
print(f"Longitud del padding analizado: {padding_analizado} bytes", "\n")

"""
RESPUESTA A PREGUNTA 2 Y 3:
En este caso particular, ambos funcionan y dan el mismo resultado.

El padding es de 1 byte (0x01), que es válido tanto para PKCS7 como X923.
PKCS7 con 1 byte: 0x01
X923 con 1 byte:  0x01
"""
