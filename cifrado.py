import base64
import boto3
from cryptography.fernet import Fernet

# 1. Conexion con AWS KMS
kms = boto3.client('kms', region_name='us-east-1')
KEY_ID = 'alias/mi-llave'


def cifrar(mensaje: str) -> dict:
    """Genera una Data Key en KMS, cifra el mensaje localmente y destruye la llave en plano."""
    # Solicitar Data Key de 256 bits a KMS (retorna texto plano y texto cifrado)
    res = kms.generate_data_key(KeyId=KEY_ID, KeySpec='AES_256')
    raw_key = res['Plaintext']
    encrypted_key = res['CiphertextBlob']

    # Cifrado local con la Data Key en texto plano
    f = Fernet(base64.urlsafe_b64encode(raw_key))
    msm_cifrado = f.encrypt(mensaje.encode('utf-8'))

    # Destruir explicitamente la llave en texto plano de memoria RAM
    del raw_key
    del f

    # Retornar el Sobre Digital
    return {
        'msm_cifrado': msm_cifrado,
        'key_cifrada': encrypted_key
    }


def descifrar(sobre: dict) -> str:
    """Pide a KMS descifrar la Data Key, descifra el mensaje local y muestra datos."""
    # KMS descifra la Data Key contenida en el sobre
    res = kms.decrypt(CiphertextBlob=sobre['key_cifrada'])
    raw_key = res['Plaintext']

    # Descifrar mensaje original
    fernet_key = base64.urlsafe_b64encode(raw_key)
    f = Fernet(fernet_key)
    msm_original = f.decrypt(sobre['msm_cifrado']).decode('utf-8')

    # Mostrar en consola llave recuperada y mensaje
    print(f"Data Key recuperada (Base64): {fernet_key.decode('utf-8')}")
    print(f"Mensaje descifrado: {msm_original}")

    # Limpieza de memoria
    del raw_key
    del fernet_key
    del f

    return msm_original


if __name__ == '__main__':
    msm = "Mensaje secreto para el examen de arquitectura"
    print("1. Cifrando mensaje y generando sobre digital...")
    sobre_digital = cifrar(msm)

    print("2. Descifrando sobre digital...")
    descifrar(sobre_digital)
