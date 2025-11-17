import rsa

# Generate receiver RSA keys for encryption
receiver_public_key, receiver_private_key = rsa.newkeys(2048)
with open("receiver_public_key.pem", "wb") as rpk_file:
    rpk_file.write(receiver_public_key.save_pkcs1('PEM'))
with open("receiver_private_key.pem", "wb") as rpk_file:
    rpk_file.write(receiver_private_key.save_pkcs1('PEM'))
