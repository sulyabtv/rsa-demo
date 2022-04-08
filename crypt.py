#!/usr/bin/env python3

# NOTE: This module requires the pycryptodomex package
#       Installation (using pip):
#           pip install pycryptodomex
#
# Sample execution input:
#
# For encryption:
# ./crypto.py -e alice.pub secret.txt secret.cip
#
# For decryption:
# ./crypto.py -d alice.prv secret.cip secret.txt

import sys
from os import urandom
from os.path import exists
from Cryptodome.Cipher import AES
import pickle

MODE_ENCRYPT = 0
MODE_DECRYPT = 1

def read_infile( infile, mode ):
    readmode = "r" if mode == MODE_ENCRYPT else "rb"
    with open( infile, readmode ) as f:
        if mode == MODE_ENCRYPT:
            return f.read()
        else:
            return pickle.load( f )

def read_keyfile( keyfile ):
    N = None
    exp = None
    with open( keyfile, "r" ) as f:
        lines = f.readlines()
        ( N, exp ) = ( int( lines[ 0 ] ), int( lines[ 1 ] ) )
    return ( N, exp )

def encrypt( keyfile, infile, outfile ):
    # First read the keyfile to get N and e
    ( N, e ) = read_keyfile( keyfile )
    # Read the infile to get plaintext
    plaintext = read_infile( infile, MODE_ENCRYPT ).encode( "utf-8" )
    # Generate random AES-128 key
    aes128_key = urandom( 16 ) # 16 bytes = 128 bits
    # Encrypt the key using RSA exponentiation
    aes128_key_enc = pow( int.from_bytes( aes128_key, "big" ), e, N )
    # Encrypt the plaintext using AES-128 EAX mode
    aes128_cipher = AES.new( aes128_key, AES.MODE_EAX )
    ciphertext, tag = aes128_cipher.encrypt_and_digest( plaintext )
    # Write nonce, tag, ciphertext and encrypted key to outfile
    with open( outfile, "wb" ) as f:
        pickle.dump( [ aes128_cipher.nonce, tag, aes128_key_enc, ciphertext ],
                     f )

def decrypt( keyfile, infile, outfile ):
    # First read the keyfile to get N and d
    ( N, d ) = read_keyfile( keyfile )
    # Read the infile to get nonce, tag, encrypted AES-128 key and ciphertext
    nonce, tag, aes128_key_enc, ciphertext = read_infile( infile, MODE_DECRYPT )
    # Obtain the AES-128 key using RSA decryption
    aes128_key = pow( aes128_key_enc, d, N )
    aes128_key = aes128_key.to_bytes( 16, byteorder="big" )
    # Decrypt the ciphertext using the key
    aes128_cipher = AES.new( aes128_key, AES.MODE_EAX, nonce )
    try:
        plaintext = aes128_cipher.decrypt_and_verify( ciphertext, tag )
    except ValueError:
        print( "Ciphertext has been corrupted!" )
        return
    with open( outfile, "w" ) as f:
        f.write( str( plaintext, 'utf-8' ) )

if __name__ == "__main__":
    assert len( sys.argv ) == 5, "Usage: ./crypt.py [-e|-d] <keyfile> <infile> <outfile>"
    if sys.argv[ 1 ] == "-e":
        mode = MODE_ENCRYPT
    elif sys.argv[ 1 ] == "-d":
        mode = MODE_DECRYPT
    else:
        assert False, "Usage: ./crypt.py [-e|-d] <keyfile> <infile> <outfile>"
    keyfile = sys.argv[ 2 ]
    infile = sys.argv[ 3 ]
    outfile = sys.argv[ 4 ]
    assert exists( keyfile ) and exists( infile ), "One or more file(s) cannot be found"
    if mode == MODE_ENCRYPT:
        encrypt( keyfile, infile, outfile )
    else:
        decrypt( keyfile, infile, outfile )
