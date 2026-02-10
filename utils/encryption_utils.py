from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from django.conf import settings
import base64

def get_private_key():
    """Carga la llave privada desde los settings de Django."""
    return serialization.load_pem_private_key(
        settings.RSA_PRIVATE_KEY.encode(),
        password=None
    )

def get_public_key():
    """Carga la llave pública desde los settings de Django."""
    return serialization.load_pem_public_key(
        settings.RSA_PUBLIC_KEY.encode()
    )

def sign_message(message: str) -> str:
    """
    Firma un mensaje usando la llave privada.
    Útil para que otros sistemas verifiquen que el mensaje proviene de este sistema.
    """
    private_key = get_private_key()
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_signature(message: str, signature_b64: str) -> bool:
    """
    Verifica una firma usando la llave pública.
    """
    public_key = get_public_key()
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def encrypt_for_system(message: str) -> str:
    """
    Cifra un mensaje usando la llave pública para que SOLAMENTE el sistema 
    (con la privada) pueda leerlo.
    """
    public_key = get_public_key()
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def decrypt_by_system(ciphertext_b64: str) -> str:
    """
    Descifra un mensaje usando la llave privada del sistema.
    """
    private_key = get_private_key()
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()
