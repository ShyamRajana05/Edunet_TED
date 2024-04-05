from flask import Flask, request, render_template
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    text = request.form['text']
    cipher_type = request.form['cipher_type']

    if cipher_type == 'caesar':
        # Generate an RSA key of appropriate size for AES encryption
        key = generate_aes_key()
        encrypted_text = caesar_encrypt(text, key)

    return render_template('result.html', text=encrypted_text, action='Encrypted')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    text = request.form['text']
    cipher_type = request.form['cipher_type']

    if cipher_type == 'caesar':
        # Generate an RSA key of appropriate size for AES encryption
        key = generate_aes_key()
        decrypted_text = caesar_decrypt(text, key)

    return render_template('result.html', text=decrypted_text, action='Decrypted')

def generate_aes_key():
    # Generate an RSA key of at least 512 bits for AES encryption
    key = rsa.generate_private_key(public_exponent=65537, key_size=512)
    # Serialize the key to bytes
    serialized_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return serialized_key

def caesar_encrypt(text, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key[:16]), modes.ECB(), backend=backend)  # Use only the first 16 bytes (128 bits) of the key
    encryptor = cipher.encryptor()

    # Pad the data to a multiple of 16 bytes
    padded_data = text.encode().ljust(16 * ((len(text) + 15) // 16), b' ')

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext.hex()


def caesar_decrypt(text, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key[:16]), modes.ECB(), backend=backend)  # Use only the first 16 bytes (128 bits) of the key
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(bytes.fromhex(text)) + decryptor.finalize()
    return decrypted_data.rstrip(b' ').decode()

if __name__ == '__main__':
    app.run(debug=True)
