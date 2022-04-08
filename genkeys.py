#!/usr/bin/env python3

# Sample execution input:
#
# ./genkeys.py alice

import sys
from os import urandom
from math import sqrt, gcd
from random import randint

small_primes = []

def init_small_primes():
    global small_primes
    small_primes = [ x for x in range ( 998 ) ]
    small_primes[ 0 : 2 ] = [ None, None ]
    for i in range( 2, int( sqrt( 997 ) ) ):
        if small_primes[ i ] == None:
            continue
        for j in range( 2, int( 997 / i ) + 1 ):
            small_primes[ i*j ] = None
    small_primes = [ x for x in small_primes if x != None ]

def test_small_primes( candidate ):
    is_prime = True
    for prime in small_primes:
        if candidate % prime == 0:
            is_prime = False
            break
    return is_prime

def miller_rabin_test( candidate ):
    # We run 40 rounds of Miller-Rabin test to check for primality
    # Step 1: Write candidate as d*2^r + 1 where d is odd
    d = candidate - 1
    r = 0
    while d % 2 == 0:
        r += 1
        d = ( d >> 1 )

    for round in range( 40 ):
        a = randint( 2, candidate - 2 )
        x = pow( a, d, candidate )
        if x == 1 or x == candidate - 1:
            continue
        for i in range( r - 1 ):
            x = pow( x, 2, candidate )
            if x == candidate - 1:
                continue
        return False
    return True

def gen_prime():
    found_prime = False
    randint = 0
    while not found_prime:
        # First generate random numbers 1024 bits long and preselect
        # by trying to divide it with small primes (<1000) 
        rand = urandom( 128 ) # 128 bytes = 1024 bits
        randint = int.from_bytes( rand, "big" )
        if( test_small_primes( randint ) ):
            # Preselected; now run Miller-Rabin primality test
            found_prime = miller_rabin_test( randint )
    return randint

def find_modular_inverse( a, n ):
    # Calculate modular inverse using the Extended Euclidean Algorithm
    # Returns ( True, inverse ) if inverse exists; ( False, None ) otherwise
    t = 0
    r = n
    new_t = 1
    new_r = a

    while new_r != 0:
        quotient = ( r // new_r )
        assert ( ( r - quotient * new_r ) < new_r ), "Python division error"
        ( t, new_t ) = ( new_t, t - ( quotient * new_t ) )
        ( r, new_r ) = ( new_r, r - ( quotient * new_r ) )

    if r > 1:
        return ( False, None )
    if t < 0:
        t += n
    return ( True, t )

def gen_keys( username ):
    # We fix e = 65537 and search for random pair of primes p & q
    # such that gcd( e, (p-1)*(q-1) ) = 1
    
    p = 0
    q = 0
    N = 0
    phi_N = 0
    e = 65537

    found_eligible_primes = False
    while not found_eligible_primes:
        p = gen_prime()
        q = gen_prime()
        N = p * q
        phi_N = ( p - 1 ) * ( q - 1 )
        ( found_eligible_primes, d ) = find_modular_inverse( e, phi_N )

    # Write private key ( N, d )
    with open( username + ".prv", "w" ) as f:
        f.write( str( N ) + "\n" + str( d ) )
    # Write public key ( N, e )
    with open( username + ".pub", "w" ) as f:
        f.write( str( N ) + "\n" + str( e ) )

if __name__ == "__main__":
    assert len( sys.argv ) == 2, "Usage: ./genkeys.py <username>"
    username = sys.argv[ 1 ]
    init_small_primes()
    gen_keys( username )
