from cryptography.fernet import Fernet
import base64, os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def get_key(password): #get a key from a password by passing it through a key derivation function and converting it to base64
    password = password.encode()
    with open('salt.txt','rb') as saltFile:
        salt = saltFile.read()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_file(key, filenameFrom, filenameTo): #encrypt a file and make a new encrypted file
    with open(filenameFrom, 'rb') as file:
        data = file.read() #read data
    fernet = Fernet(key)
    encrypted=fernet.encrypt(data)
    with open(filenameTo, 'wb') as file:
        file.write(encrypted) #write encrypted data to new file
    os.remove(filenameFrom) #delete original file


def decrypt_file(key, filenameFrom, filenameTo): #decrypt a file and save the plaintext in a new file
    with open(filenameFrom,'rb') as file:
        encrypted=file.read() #read encrypted data
    fernet = Fernet(key)
    decrypted=fernet.decrypt(encrypted)
    with open(filenameTo, 'wb') as file:
        file.write(decrypted) #write decrypted data to new file
    os.remove(filenameFrom) #delete original file

def new_salt():
    with open('salt.txt','wb') as saltFile:
        saltFile.write(os.urandom(16))


print("""1. Encrypt a file
2. Decrypt a file
3. Generate a new salt
4. Exit""")

choice = input("Please select an option: ")
while choice != '4':
    if choice == '1':
        filenameFrom = input("\nPlease enter the location of the plaintext file to be encrypted: ")
        filenameTo = input("Please enter a location for the new encrypted file: ")
        password = input("Enter a password: ")
        key = get_key(password)
        encrypt_file(key, filenameFrom, filenameTo)

    elif choice == '2':
        filenameFrom = input("\nPlease enter the location of the encrypted file to be decrypted: ")
        filenameTo = input("Please enter a location for the new decrypted file: ")
        password = input("Enter the password: ")
        key = get_key(password)
        decrypt_file(key, filenameFrom, filenameTo)

    elif choice == '3':
        print("\nIf you generate a new salt you won't be able to decrypt any files encrypted with the current salt.")
        sure = input("Are you sure you want to generate a new salt? (y/n): ")
        if sure.lower() == 'y':
            new_salt()

    print("""
1. Encrypt a file
2. Decrypt a file
3. Generate a new salt
4. Exit""")
    choice = input("Please select an option: ")
