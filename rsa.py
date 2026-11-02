# time: stopwatch to measure how long each step takes
import time
# secrets: used to create a random message
import secrets
# gcd: checks whether two numbers share a common factor
from math import gcd 
# randprime: gives a random prime number inside a given range
from sympy import randprime
# this function generates the public key and the private key
def rsa(bits):
    # e is the public exponent, fixed at 65537 (prime, fast, safe)
    e=65537
    # keep trying until we get a valid pair of primes
    while True:
        # p is a random prime, about half the key size
        p=randprime(2**(bits//2-1),2**(bits//2))
        # q is another random prime, about half the key size
        q=randprime(2**(bits//2-1),2**(bits//2))
        # the two primes must be different, otherwise try again
        if p==q:
            continue
        # n is the modulus, n = p * q, its size is the key size
        n=p*q
        # phi is the helper number, phi = (p-1) * (q-1)
        phi=(p-1)*(q-1)
        # e must have no common factor with phi, otherwise d cannot be found
        if gcd(e,phi)==1:
            break
    # d is the private exponent, the modular inverse of e (e * d leaves remainder 1 mod phi)
    d=pow(e,-1,phi)
    # return public key (e, n) and private key (d, n)
    return (e,n),(d,n)
# this function runs the experiment
def main():
    # key sizes to test
    key_sizes=[512,1024,2048]
    # message sizes to test
    msg_sizes=[64,128,256,512]
    # outer loop: one run for each key size
    for bits in key_sizes:
        # start the stopwatch
        start=time.perf_counter()
        # generate the keys
        public,private=rsa(bits)
        # stop the stopwatch: this is the key generation time
        key_time=time.perf_counter()-start
        print("\n--------------------------------")
        print(f"Rsa key size {bits} bits ")
        print(f"Key generation time {key_time:.6f} sec")
        # inner loop: one run for each message size
        for size in msg_sizes:
            # message must be smaller than n, so skip if it is too big
            if size>=public[1].bit_length():
                continue
            # create a random message of up to 'size' bits
            msg=secrets.randbits(size)
            # start the stopwatch for encryption
            start=time.perf_counter()
            # encryption: c = m^e mod n (locks the message)
            encrypt=pow(msg,public[0],private[1])
            # time taken to encrypt
            enc_time=time.perf_counter()-start
            # decryption: m = c^d mod n (unlocks the message)
            decrypt=pow(encrypt,private[0],public[1])
            # note: start is not reset here, so this time is measured from the start of encryption
            dec_time=time.perf_counter()-start
            print("--------------------------------")
            print(f"Message size {size} bits ")
            print(f"Encryption time {enc_time:.6f} sec")
            print(f"Decryption time {dec_time:.6f} sec")
            # True means the decrypted message is the same as the original message
            print("Sucessful : ",msg==decrypt)
# run main() only when this file is executed directly
if __name__=="__main__":
    main()


"""
==================== VARIABLES ====================

Inside rsa(bits)
    bits  : key size we want (512 / 1024 / 2048)
    e     : public exponent, fixed at 65537
    p, q  : two different random primes, each about half the key size
    n     : modulus = p * q (its size is the key size, part of both keys)
    phi   : helper number = (p-1) * (q-1), used only to find d, stays secret
    d     : private exponent, modular inverse of e

Inside main()
    key_sizes : list of key sizes to test
    msg_sizes : list of message sizes to test
    bits      : current key size in the outer loop
    start     : stopwatch reading taken before a step begins
    public    : public key (e, n)   -> public[0] = e, public[1] = n
    private   : private key (d, n)  -> private[0] = d, private[1] = n
    key_time  : time taken to generate keys
    size      : current message size in the inner loop
    msg       : random original message
    encrypt   : ciphertext = msg^e mod n
    enc_time  : time taken to encrypt
    decrypt   : decrypted message = encrypt^d mod n (should equal msg)
    dec_time  : decryption time reading (measured from the same start as encryption)

Functions used
    time.perf_counter()  : precise stopwatch
    secrets.randbits(k)  : random number of up to k bits
    gcd(a, b)            : greatest common divisor
    randprime(a, b)      : random prime between a and b
    pow(a, b, m)         : (a ** b) mod m, fast
    pow(e, -1, phi)      : modular inverse (finds d)


==================== SPEECH ====================

Opening
"Good morning, sir/ma'am. My assignment is to implement the RSA algorithm and
compare how long key generation, encryption and decryption take for different
key sizes and message sizes."

What is RSA
"RSA is a way of sending secret messages using two keys. The public key is
shared with everyone and is used to encrypt. The private key is kept secret by
the receiver and is used to decrypt. It is like a padlock: I give open padlocks
to everyone, anyone can lock a box with them, but only I have the key to open
it. It is safe because multiplying two big primes is easy, but finding those
primes from the answer is almost impossible."

Variables
"p and q are two random primes, each about half the key size. n is p times q,
called the modulus, and its size is the key size. phi is (p minus 1) times
(q minus 1), a helper number used to create the private key; it stays secret.
e is the public exponent, fixed at 65537: it is prime, has only two 1-bits so
encryption is fast, and is big enough to avoid attacks on tiny values like 3.
d is the private exponent, the modular inverse of e. The public key is (e, n)
and the private key is (d, n)."

How the code works
"The rsa function picks two different primes, calculates n and phi, checks that
e and phi have no common factor, then calculates d using Python's pow with -1,
which gives the modular inverse. The main function runs the experiment: for
each key size it measures key generation time, then for each message size it
creates a random message, encrypts it with m to the power e mod n, and decrypts
it with c to the power d mod n, while measuring the time. Finally it checks
that the decrypted message equals the original; True means RSA worked. A
message must be smaller than n, so impossible combinations like a 512-bit
message with a 512-bit key are skipped."

Results
"One, key generation is the slowest because finding huge primes takes many
attempts. Two, encryption is very fast because e is small. Three, decryption
is slower because d is as large as n. Message size hardly changes the time;
key size is what matters."

Conclusion
"A bigger key gives more security but is slower. Key generation and decryption
are the costly parts, while encryption stays fast. Thank you."

==================== IF GUIDE ASKS ====================
What is phi?   A helper number (p-1)*(q-1) used to find the private key; secret.
What is pow?   Python's power function; with 3 arguments it gives power and
               remainder together, quickly; with -1 it gives the modular inverse.
Why 65537?     Prime, only two 1-bits (fast encryption), safe from small-e attacks.
Why half-size p and q?  So their product n comes out to about the full key size.
Why skip some message sizes?  The message must be smaller than n, otherwise
               decryption will not return the original message.
"""