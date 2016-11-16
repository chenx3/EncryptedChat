from Crypto.PublicKey import RSA

key = RSA.generate(2048)

# export the entire key pair in PEM format
ofile = open('user_steve.pem', 'w')
ofile.write(key.exportKey('PEM'))
ofile.close()

# export only the public key in PEM format
ofile = open('steve-pubkey.pem', 'w')
ofile.write(key.publickey().exportKey('PEM'))
ofile.close()

# export the entire key pair in DER format
#ofile = open('rsa-test-key.der', 'w')
#ofile.write(key.exportKey('DER'))
#ofile.close()

# export only the public key in DER format
#ofile = open('rsa-test-pubkey.der', 'w')
#ofile.write(key.publickey().exportKey('DER'))
#ofile.close()
