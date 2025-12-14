import jks
import base64
from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305


def leer_clave_keystore(keystore_path, keystore_password, tag):
    try:
        keystore = jks.KeyStore.load(keystore_path, keystore_password)

        # Buscar la entrada con el tag especificado
        if tag in keystore.entries:
            entry = keystore.entries[tag]

            # Dependiendo del tipo de entrada, extraer la clave
            if isinstance(entry, jks.SecretKeyEntry):
                clave = entry.key
                return clave

            elif isinstance(entry, jks.PrivateKeyEntry):
                return None

            else:
                return None
        else:
            return None

    except Exception as _e:
        return None


clave = leer_clave_keystore(".assets/KeyStorePracticas", "123456", "cifrado-sim-chacha20-256")
nonce_b64 = "9Yccn/f5nJJhAt2S"
nonce = base64.b64decode(nonce_b64)
texto_sin_cifrar = "KeepCoding te enseña a codificar y a cifrar"


print("=" * 70)
print("COMPARACIÓN: ChaCha20 vs ChaCha20-Poly1305")
print("=" * 70)
print(f"\nNonce (base64): {nonce_b64}")
print(f"Nonce (hex): {nonce.hex()}")
print(f"Longitud nonce: {len(nonce)} bytes")


# ============================================================================
# 1. ChaCha20 SOLO (Sistema Actual - SOLO CONFIDENCIALIDAD)
# ============================================================================
print("\n[1] ChaCha20 (Sistema Actual)")
print("-" * 70)

if clave:
    # Cifrar con ChaCha20
    cipher = ChaCha20.new(key=clave, nonce=nonce)
    texto_cifrado_chacha20 = cipher.encrypt(texto_sin_cifrar.encode('utf-8'))

    texto_cifrado_b64 = base64.b64encode(texto_cifrado_chacha20).decode('utf-8')

    print(f"Texto original: {texto_sin_cifrar}")
    print(f"Clave (hex): {clave.hex()}")
    print(f"Texto cifrado (hex): {texto_cifrado_chacha20.hex()}")
    print(f"Texto cifrado (base64): {texto_cifrado_b64}")
    print(f"Longitud cifrado: {len(texto_cifrado_chacha20)} bytes")

    # Demostrar descifrado
    cipher_decrypt = ChaCha20.new(key=clave, nonce=nonce)
    texto_descifrado = cipher_decrypt.decrypt(texto_cifrado_chacha20).decode('utf-8')
    print(f"Texto descifrado: {texto_descifrado}")
    print(f"✓ Verificación: {texto_descifrado == texto_sin_cifrar}")

    print("\n⚠️  PROBLEMA: No hay garantía de INTEGRIDAD")
    print("   - Un atacante podría modificar el texto cifrado")
    print("   - No detectaríamos manipulaciones maliciosas")
    print("   - Solo tenemos CONFIDENCIALIDAD, no AUTENTICACIÓN")
else:
    print("ERROR: No se pudo leer la clave del keystore")

# ============================================================================
# 2. ChaCha20-Poly1305 (PROPUESTA MEJORADA - CONFIDENCIALIDAD + INTEGRIDAD)
# ============================================================================
print("\n\n[2] ChaCha20-Poly1305 (Propuesta Mejorada - AEAD)")
print("-" * 70)
print("MEJORA: Cifrado Autenticado con Datos Asociados (AEAD)")

if clave:
    # Datos adicionales autenticados (AAD) - opcional
    # Son metadatos que queremos autenticar pero NO cifrar
    aad = b"KeepCoding-2024-Practica-Criptografia"

    # Cifrar Y autenticar con ChaCha20-Poly1305
    cipher_poly = ChaCha20_Poly1305.new(key=clave, nonce=nonce)
    cipher_poly.update(aad)  # Añadir AAD
    texto_cifrado_poly, tag = cipher_poly.encrypt_and_digest(texto_sin_cifrar.encode('utf-8'))

    # Resultado: texto_cifrado + tag de autenticación (16 bytes)
    resultado_completo = texto_cifrado_poly + tag
    texto_cifrado_poly_b64 = base64.b64encode(resultado_completo).decode('utf-8')

    print(f"Texto original: {texto_sin_cifrar}")
    print(f"Clave (hex): {clave.hex()}")
    print(f"AAD (metadatos): {aad.decode('utf-8')}")
    print(f"Texto cifrado (hex): {texto_cifrado_poly.hex()}")
    print(f"Tag Poly1305 (hex): {tag.hex()}")
    print(f"Resultado completo (base64): {texto_cifrado_poly_b64}")
    print("\nLongitudes:")
    print(f"  - Texto cifrado: {len(texto_cifrado_poly)} bytes")
    print(f"  - Tag Poly1305 (MAC): {len(tag)} bytes")
    print(f"  - Total: {len(resultado_completo)} bytes")

    # Descifrar Y verificar integridad
    print("\nDescifrado y verificación:")
    try:
        cipher_decrypt = ChaCha20_Poly1305.new(key=clave, nonce=nonce)
        cipher_decrypt.update(aad)
        texto_descifrado_poly = cipher_decrypt.decrypt_and_verify(texto_cifrado_poly, tag)
        print(f"Texto descifrado: {texto_descifrado_poly.decode('utf-8')}")
        print(f"✓ Verificación: {texto_descifrado_poly.decode('utf-8') == texto_sin_cifrar}")
        print("✓ Verificación de integridad: EXITOSA")
        print("✓ Verificación de autenticidad: EXITOSA")
    except Exception as e:
        print(f"✗ Error en verificación: {e}")

    print("\n✓ VENTAJAS de ChaCha20-Poly1305:")
    print("   • Confidencialidad: El texto está cifrado")
    print("   • Integridad: Detecta cualquier modificación del cifrado")
    print("   • Autenticidad: Verifica que el emisor tiene la clave correcta")
    print("   • AAD: Protege metadatos sin cifrarlos")
    print("   • Eficiencia: Un solo paso para cifrar y autenticar")
    print("   • Estándar: RFC 8439, usado en TLS 1.3, WireGuard, Signal")
