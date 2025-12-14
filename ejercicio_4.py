import jwt

secret_key = "Con KeepCoding aprendemos"
jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c3VhcmlvIjoiRG9uIFBlcGl0byBkZSBsb3MgcGFsb3RlcyIsInJvbCI6ImlzTm9ybWFsIiwiaWF0IjoxNjY3OTMzNTMzfQ.gfhw0dDxp6oixMLXXRP97W4TDTrv0y7B5YjD0U8ixrE"

# ¿Qué algoritmo de firma hemos realizado?
header = jwt.get_unverified_header(jwt_token)
print("Algoritmo de firma:", header["alg"])  # HS256

decoded_payload = jwt.decode(jwt_token, secret_key, algorithms=[header["alg"]])  # {'usuario': 'Don Pepito de los palotes', 'rol': 'isNormal', 'iat': 1667933533}
print("Body del JWT:", decoded_payload)

jwt_token_hacker = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c3VhcmlvIjoiRG9uIFBlcGl0byBkZSBsb3MgcGFsb3RlcyIsInJvbCI6ImlzQWRtaW4iLCJpYXQiOjE2Njc5MzM1MzN9.krgBkzCBQ5WZ8JnZHuRvmnAZdg4ZMeRNv2CIAODlHRI"

# ¿Qué está intentando realizar?
## Primero decodificamos SIN verificar para ver qué contiene
payload_hacker = jwt.decode(jwt_token_hacker, options={"verify_signature": False})
print("\nPayload del hacker:", payload_hacker)
print("El hacker modificó el campo 'rol' de 'isNormal' a:", payload_hacker["rol"])  # {'usuario': 'Don Pepito de los palotes', 'rol': 'isAdmin', 'iat': 1667933533}

# ¿Qué ocurre si intentamos validarlo con pyjwt?
try:
    payload_verificado = jwt.decode(jwt_token_hacker, key=secret_key, algorithms=["HS256"])
    print("✅ Token válido:", payload_verificado)

except jwt.InvalidSignatureError:
    print("❌ ERROR: InvalidSignatureError: La firma no es válida. El token ha sido modificado.")
except jwt.DecodeError as e:
    print("❌ ERROR: DecodeError -", e)
except Exception as e:
    print("❌ ERROR:", type(e).__name__, "-", e)
