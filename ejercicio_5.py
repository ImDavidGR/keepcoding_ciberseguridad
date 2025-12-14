texto_plano = "En KeepCoding aprendemos cómo protegernos con criptografía"

hash_sha3 = "bced1be95fbd85d2ffcce9c85434d79aa26f24ce82fbd4439517ea3f072d56fe"
hash_sha2 = "4cec5a9f85dcc5c4c6ccb603d124cf1cdc6dfe836459551a1044f4f2908aa5d63739506f6468833d77c07cfd69c488823b8d858283f1d05877120e8c5351c833"


def verificar_hash_type(hex_hash, hash_family):
    len_hash = len(hex_hash)

    ## Convertimos a bytes (2 caracteres hexadecimales = 1 byte)
    len_hash_bytes = len_hash // 2

    ## Convertimos a bits (1 byte = 8 bits)
    len_hash_bits = len_hash_bytes * 8

    return f"Tipo de {hash_family}: {hash_family}-{len_hash_bits}"


print(verificar_hash_type(hash_sha3, "SHA3"))  # Tipo de SHA3: SHA3-256
print(verificar_hash_type(hash_sha2, "SHA2"))  # Tipo de SHA2: SHA2-512
