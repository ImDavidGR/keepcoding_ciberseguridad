1. Primera propuesta: SHA-1
- Actualmente se considera inseguro y obsoleto debido a vulnerabilidades descubiertas en 2005.
- En 2010 el NIST lo empieza a prohibir para cualquier uso en el área de la criptografía.
- En 2017 se descubre un ataque de colisión en contra de este algoritmo.
- Su velocidad de cálculo es un problema: aunque útil para integridad de datos, facilita ataques de fuerza bruta o diccionario.

Conclusión: SHA-1 no es recomendable para almacenar contraseñas.

2. Segunda propuesta: SHA-256
- Más seguro que SHA-1; no se conocen colisiones prácticas. Sin embargo sigue siendo demasiado rápido para contraseñas, permitiendo que un atacante pueda probar millones de combinaciones por segundo.

Posible fortalecimiento:
- Salt: Valor aleatorio único por usuario que ayuda a prevenir ataques con tablas rainbow.
- Iteraciones: Aplicar SHA-256 varias veces para ralentizar los ataques de fuerza bruta.

3. Mejor alternativa
Aunque actualmente contamos con SHA-3 como evolución de SHA-2 tenemos otras mejores opciones como bcrypt, scrypt, argon2, siendo este último el más recomendado actualmente.

Ventajas:
- Integran salt automáticamente.
- Se pueden configurar para que sean más lentos y usen memoria, dificultando así ataques incluso con hardware especializado.
