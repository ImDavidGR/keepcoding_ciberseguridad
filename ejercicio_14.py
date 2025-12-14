import jks
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


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


keystore_path = "./assets/KeyStorePracticas"
keystore_password = "123456"
tag = "cifrado-sim-aes-256"

device_id_hex = "e43bb4067cbcfab3bec54437b84bef4623e345682d89de9948fbb0afedc461a3"
salt = bytes.fromhex(device_id_hex)

result = leer_clave_keystore(keystore_path, keystore_password, tag)
if result["success"]:
    key = result["key"]
else:
    raise Exception(result["error"])


hkdf = HKDF(algorithm=hashes.SHA512(), length=32, salt=salt)
key_aes = hkdf.derive(key)

print(f"Clave AES: {key_aes.hex()}")
