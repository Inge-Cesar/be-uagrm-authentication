# Documentación: Cifrado Asimétrico (RSA)

Este sistema utiliza el algoritmo **RSA** para garantizar la integridad y confidencialidad en la comunicación entre el sistema central y los sistemas periféricos.

## Concepto General

En este esquema:
- **Llave Privada (Private Key)**: Es de uso exclusivo del sistema central. Se utiliza para **firmar** datos (garantizar origen) o para **descifrar** datos enviados exclusivamente al sistema.
- **Llave Pública (Public Key)**: Es compartida con los sistemas periféricos. Se utiliza para **verificar** firmas del sistema central o para **cifrar** datos que solo el sistema central debe leer.

## Implementación Técnica

### 1. Variables de Entorno
Se han añadido dos variables al archivo `.env`:
- `RSA_PRIVATE_KEY`: El contenido PEM de la llave privada.
- `RSA_PUBLIC_KEY`: El contenido PEM de la llave pública.

### 2. Utilidades de Cifrado
Las funciones se encuentran en `utils/encryption_utils.py`:

- `sign_message(message)`: El sistema firma un texto con su llave privada. Retorna una firma en Base64.
- `verify_signature(message, signature_b64)`: Un sistema externo usa la llave pública para confirmar que el mensaje no fue alterado y viene de nosotros.
- `encrypt_for_system(message)`: Un sistema externo usa la llave pública para cifrar un dato sensible.
- `decrypt_by_system(ciphertext_b64)`: El sistema central usa su llave privada para leer ese dato.

## Ejemplo de Uso en Python

```python
from utils.encryption_utils import sign_message, verify_signature

# 1. El sistema central firma algo
mensaje = "Datos sensibles de usuario"
firma = sign_message(mensaje)

# 2. Otro sistema verifica la autenticidad
es_valido = verify_signature(mensaje, firma)
print(f"¿Es auténtico? {es_valido}")
```

## Seguridad
- La llave privada **NUNCA** debe salir del servidor central.
- La llave pública puede distribuirse libremente.
