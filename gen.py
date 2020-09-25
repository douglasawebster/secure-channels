from Crypto.PublicKey import RSA

def generate_keys():

    # Generating key pair for Alice
    alice_key = RSA.generate(2048)
    alice_private_key = alice_key.export_key('PEM')
    alice_public_key = alice_key.publickey().export_key('PEM')

    # Generating key pair for Bob
    bob_key = RSA.generate(2048)
    bob_private_key = bob_key.export_key('PEM')
    bob_public_key = bob_key.publickey().export_key('PEM')

    # Writing Alice's keys
    f = open('./keys/alice_priv.pem','wb')
    f.write(alice_private_key)
    f.close()
    f = open('./keys/alice_public.pem','wb')
    f.write(alice_public_key)
    f.close()

    # Writing Bob's keys
    f = open('./keys/bob_priv.pem', 'wb')
    f.write(bob_private_key)
    f.close()
    f = open('./keys/bob_public.pem', 'wb')
    f.write(bob_public_key)
    f.close()

generate_keys()