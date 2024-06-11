import boto3
import random
import string, os

from django.conf import settings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64


class UserViewUtils:

    def __init__(self) -> None:
        pass

    def get_random_string(self, length):
        # With combination of lower and upper case
        result_str = ''.join(random.choice(string.ascii_letters)
                                for i in range(length))
        # print random string
        return result_str

    def send_mail(toAddress, subject, html_message):
        ses_client = boto3.client("ses", aws_access_key_id=settings.AWS_ACCESS_KEY_ID, aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY, region_name=settings.AWS_SES_REGION_NAME)
        CHARSET = "UTF-8"

        response = ses_client.send_email(
            Destination={
                "ToAddresses": toAddress,
            },
            Message={
                "Body": {
                    "Html": {
                        "Charset": CHARSET,
                        "Data": html_message,
                    }
                },
                "Subject": {
                    "Charset": CHARSET,
                    "Data": subject,
                },
            },
            Source=settings.DEFAULT_FROM_EMAIL,
        )
        return response


def encrypt_private_key(private_key, encryption_key):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)

    # Pad the private key to a multiple of 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_private_key = padder.update(bytes(private_key, 'utf-8')) + padder.finalize()

    # Create a cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())

    # Encrypt the padded private key
    encryptor = cipher.encryptor()
    encrypted_private_key = encryptor.update(padded_private_key) + encryptor.finalize()

    # Return the IV and the encrypted private key
    return iv + encrypted_private_key

def decrypt_private_key(encrypted_data, encryption_key):
    # Extract the IV from the encrypted data
    iv = encrypted_data[:16]

    # Extract the encrypted private key
    encrypted_private_key = encrypted_data[16:]

    # Create a cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())

    # Decrypt the encrypted private key
    decryptor = cipher.decryptor()
    decrypted_private_key = decryptor.update(encrypted_private_key) + decryptor.finalize()

    # Unpad the decrypted private key
    unpadder = padding.PKCS7(128).unpadder()
    private_key = unpadder.update(decrypted_private_key) + unpadder.finalize()

    return private_key.decode('utf-8')
