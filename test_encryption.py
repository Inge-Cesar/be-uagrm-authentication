import os
import django
import sys

# Setup Django environment
sys.path.append('c:\\Users\\CESAR\\Desktop\\UAGRM\\PROYECTOS-SEGURIDAD\\authentication-service-main')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from utils.encryption_utils import sign_message, verify_signature, encrypt_for_system, decrypt_by_system

def test_rsa():
    mensaje_original = "Prueba de seguridad RSA 123"
    
    # 1. Test Firma
    print(f"Original: {mensaje_original}")
    firma = sign_message(mensaje_original)
    print(f"Firma: {firma[:30]}...")
    
    if verify_signature(mensaje_original, firma):
        print("✅ Verificación de firma: EXITOSA")
    else:
        print("❌ Verificación de firma: FALLIDA")
        
    # 2. Test Cifrado
    cifrado = encrypt_for_system(mensaje_original)
    print(f"Cifrado: {cifrado[:30]}...")
    
    descifrado = decrypt_by_system(cifrado)
    if descifrado == mensaje_original:
        print("✅ Cifrado/Descifrado: EXITOSO")
    else:
        print("❌ Cifrado/Descifrado: FALLIDO")

if __name__ == "__main__":
    test_rsa()
