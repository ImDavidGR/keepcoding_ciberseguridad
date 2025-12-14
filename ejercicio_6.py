import jks
import hmac
import hashlib


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


def calcular_hmac_sha256(clave, mensaje):
    hmac_generator = hmac.new(clave, mensaje.encode('utf-8'), hashlib.sha256)
    return hmac_generator.hexdigest()


keystore_path = "./assets/KeyStorePracticas"
keystore_password = "123456"
tag = "hmac-sha256"
message = "Siempre existe más de una forma de hacerlo, y más de una solución válida."

key = leer_clave_keystore(keystore_path, keystore_password, tag)

if key is None or not key.get("success"):
    print("Error al leer la clave del keystore:", key.get("error"))
else:
    hmac_resultado = calcular_hmac_sha256(key.get("key"), message)
    print("HMAC-SHA256:", hmac_resultado)
