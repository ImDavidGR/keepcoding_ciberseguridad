import gnupg

gpg = gnupg.GPG()

# Imoprtamos las claves. Las abrimos en modo binario
with open("./assets/Pedro-publ.txt", 'rb') as f:
    pedro_public_key = gpg.import_keys(f.read())

with open("./assets/RRHH-publ.txt", 'rb') as f:
    rrhh_public_key = gpg.import_keys(f.read())

with open("./assets/RRHH-priv.txt", 'rb') as f:
    rrhh_private_key = gpg.import_keys(f.read())


# Tarea 1: Verificar la firma del mensaje de Pedro usando su clave pública
## Leemos el mensaje firmado
with open("./assets/MensajeRespoDeRaulARRHH.sig", 'rb') as f:
    signed_message = f.read()

## Verificamos la firma
verified = gpg.verify(signed_message)
print(f"Firma valida: {verified.valid}")
print(f"Firmado por: {verified.username}")
print(f"Fingerprint: {verified.fingerprint}")
print(f"Fecha de firma: {verified.sig_timestamp}\n")


for k in gpg.list_keys():
    print(k['uids'], k['fingerprint'])


# Tarea 2: Firmar el mensaje de respuesta usando la clave privada de RRHH
response_message = "Viendo su perfil en el mercado, hemos decidido ascenderle y mejorarle un 25% su salario.\nSaludos."

## Buscamos el fingerprint de la clave privada de RRHH
private_keys = gpg.list_keys(secret=True)
rrhh_private_key_fingerprint = None
for key in private_keys:
    if "RRHH" in key['uids'][0]:
        rrhh_private_key_fingerprint = key['fingerprint']
        break

## Si no se encuentra, usamos la primera clave privada disponible
if not rrhh_private_key_fingerprint and private_keys:
    rrhh_fingerprint = private_keys[0]['fingerprint']

## Firmamos el mensaje de respuesta
signed_response = gpg.sign(response_message, keyid=rrhh_private_key_fingerprint, passphrase="123456", detach=False)
with open("./results/MensajeFirmadoDeRRHH.sig", 'w') as f:
    f.write(str(signed_response))

# Tarea 3: Cifrar el mensaje confidencial usando las claves públicas de Pedro y RRHH
confidential_message = "Estamos todos de acuerdo, el ascenso será el mes que viene, agosto, si no hay sorpresas."

## Obtenemos los fingerprints de las claves públicas
pedro_public_key_fingerprint = None
rrhh_public_key_fingerprint = None

public_keys = gpg.list_keys()
for key in public_keys:
    uids = str(key.get('uids', []))
    if "Pedro" in uids and not pedro_public_key_fingerprint:
        pedro_public_key_fingerprint = key['fingerprint']
    if "RRHH" in uids and not rrhh_public_key_fingerprint:
        rrhh_public_key_fingerprint = key['fingerprint']

## Coframos el mensaje confidencial para Pedro y RRHH
recipients = [pedro_public_key_fingerprint, rrhh_public_key_fingerprint]
message_encrypted = gpg.encrypt(confidential_message, recipients, passphrase="123456", always_trust=True)

with open("./results/MensajeConfidencialParaPedroYRRHH.gpg", 'w') as f:
    f.write(str(message_encrypted))
