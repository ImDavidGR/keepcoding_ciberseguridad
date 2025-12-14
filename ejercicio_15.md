0. Análisis del bloque: (https://paymentcardtools.com/key-block)
D0144D0AB00S000042766B9265B2DF93AE6E29B58135B77A2F616C8D514ACDBE6A5626F79FA7B4071E9EE1423C6D7970FA2B965D18B23922B5B2E5657495E03CD857FD37018E111B


| Offset| Field                | Value    | Meaning |
|-------|---------------------------|------|-----------------------------------------------------------------------|
| 0     | Version ID                | D    | TR-31 Key Block protected using the AES Key Derivation Binding Method |
| 1-4   | Key Block length          | 0144 | Total length of key block                                             |
| 5-6   | Key usage                 | D0   | Data Encryption Key (Generic)                                         |
| 7     | Algorithm                 | A    | AES                                                                   |
| 8     | Mode of use               | B    | Both encryption and decryption                                        |
| 9-10  | Key Version Number        | 00   | Key versioning is not used for this key                               |
| 11    | Exportability             | S    | Sensitive, exportable under untrusted key                             |
| 12-13 | Number of optional blocks | 00   | No optional blocks                                                    |
| 14-15 | Reserved for future use   | 00   |                                                                       |

Encrypted Key Data (120 bytes)
42766B9265B2DF93AE6E29B58135B77A2F616C8D515ACDBE6A5626F79FA7B4071E9EE1423C6D7970FA2B965D18B23922B5B2E5657495E03CD857FD37

Key Block Authenticator (MAC)
018E111B

1. ¿Con qué algoritmo se ha protegido el bloque de clave?
AES (el bloque TR-31 está cifrado con AES, byte 7 = A)

2. ¿Para qué algoritmo se ha definido la clave?
AES (clave de cifrado de datos, byte 5-6 = D0)

3. ¿Para qué modo de uso se ha generado?
Tanto para cifrar como para descifrar datos (byte 8 = B, "Both")

4. ¿Es exportable?
Sí, se puede exportar de forma segura bajo clave no confiable (byte 11 = S)

5. ¿Para qué se puede usar la clave?
Para cifrar y descifrar datos sensibles

6. ¿Qué valor tiene la clave?
Para obtenerla hay que "desenvolver" (unwrap) el bloque cifrado usando AES Key Wrap con la clave de transporte: A1A10101010101010101010101010102.
El resultado será la clave de datos real en hexadecimal.