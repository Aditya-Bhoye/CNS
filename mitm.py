# =====================================================================
# Assignment 5: Diffie-Hellman Key Exchange with MITM Attack
# Aim: To understand Diffie-Hellman key exchange and demonstrate how an
#      unauthenticated key exchange is vulnerable to a Man-in-the-Middle attack.
# =====================================================================

import hashlib   # used for SHA-256 to turn the shared number into a 32-byte key
import secrets   # cryptographically secure random numbers (better than 'random')


# ---------------------------------------------------------------------
# Helper 1: converts the DH shared secret (a small number) into a
# fixed-length 256-bit (32 byte) key using SHA-256
# ---------------------------------------------------------------------
def key_gen(key):
    return hashlib.sha256(str(key).encode()).digest()


# ---------------------------------------------------------------------
# Helper 2: XOR "encryption". Each byte of the message is XORed with a
# byte of the key (key repeats using i % len(key)). Returns bytes.
# ---------------------------------------------------------------------
def encrypt(text,key):
    data=text.encode()
    return bytes(b^key[i%len(key)] for i,b in enumerate(data))


# ---------------------------------------------------------------------
# Helper 3: XOR is symmetric, so decrypting = XORing again with the same
# key. The result is decoded from bytes back to a readable string.
# ---------------------------------------------------------------------
def decrypt(text,key):
    return bytes(b^key[i%len(key)] for i,b in enumerate(text)).decode()


def main():
    # ---- Step 1: Public parameters (known to everyone, including attacker) ----
    # p = prime modulus, g = generator. Small values used only for demonstration.
    p,g=23,5

    # ---- Step 2: Private keys of Alice (a) and Bob (b), random in range 1..p-2 ----
    a,b=secrets.randbelow(p-2)+1,secrets.randbelow(p-2)+1

    # ---- Step 3: Public keys: A = g^a mod p (Alice), B = g^b mod p (Bob) ----
    A,B=pow(g,a,p),pow(g,b,p)
    print(f"Alice private key {a} and public key {A} ")
    print(f"Bob private key {b} an public key {B} ")

    # ---- Step 4: Normal Diffie-Hellman exchange ----
    # Alice computes B^a mod p, Bob computes A^b mod p. Both equal g^(ab) mod p.
    alice_key=pow(B,a,p)
    bob_key=pow(A,b,p)
    print(f"Alice shared key {alice_key}")
    print(f"Bob shared key {bob_key}")

    # ---- Step 5: Attacker (MITM) creates TWO key pairs ----
    # m1/M1 is used to talk to Alice, m2/M2 is used to talk to Bob
    m1,m2=secrets.randbelow(p-2)+1,secrets.randbelow(p-2)+1
    M1,M2=pow(g,m1,p),pow(g,m2,p)

    # ---- Step 6: Public key replacement (the actual attack) ----
    # Alice's public key A never reaches Bob, M2 is delivered instead.
    # Bob's public key B never reaches Alice, M1 is delivered instead.
    print(f"Alice sends {A} attacker replaces with {M2} and forward to Bob")
    print(f"Bob send {B} attacker replaces with {M1} and forward to Alice")

    # ---- Step 7: Separate shared keys (alice_key / bob_key are reused here) ----
    # Alice-Attacker pair: Alice computes M1^a, attacker computes A^m1 (same value)
    alice_key=key_gen(pow(M1,a,p))
    attacker_alice=key_gen(pow(A,m1,p))

    # Bob-Attacker pair: Bob computes M2^b, attacker computes B^m2 (same value)
    bob_key=key_gen(pow(M2,b,p))
    attacker_bob=key_gen(pow(B,m2,p))

    # ---- Step 8: Verify each pair holds the same key ----
    print("Attacker key matches with Alice : ",attacker_alice==alice_key)
    print("Attacker key matches with Bob : ",attacker_bob==bob_key)

    # ---- Step 9: Alice types a message and encrypts it with HER key
    # (the one she shares with the attacker, thinking it is Bob's) ----
    text=input("Alice msg : ")
    encrypted=encrypt(text,alice_key)

    # ---- Step 10: Attacker intercepts the ciphertext and decrypts it using the
    # key he shares with Alice, so he reads the plaintext ----
    intercepted=decrypt(encrypted,attacker_alice)
    print("Attacker reads : ",intercepted)

    # ---- Step 11: Attacker re-encrypts with the key he shares with Bob and
    # forwards it ----
    forward=encrypt(intercepted,attacker_bob)

    # ---- Step 12: Bob decrypts with his key and sees the original message,
    # unaware that it was read (or could have been modified) on the way ----
    recieved=decrypt(forward,bob_key)
    print("Bob received : ",recieved)


# Runs main() only when this file is executed directly
if __name__=="__main__":
    main()


# =====================================================================
# VARIABLES
# =====================================================================
# p, g              : public prime (23) and generator (5)
# a, b              : private keys of Alice and Bob (random, 1 to p-2)
# A, B              : public keys of Alice and Bob; A = g^a mod p, B = g^b mod p
# alice_key         : first the normal DH secret B^a mod p; later reassigned to
#                     Alice's 256-bit key shared with the attacker
# bob_key           : first the normal DH secret A^b mod p; later reassigned to
#                     Bob's 256-bit key shared with the attacker
# m1, m2            : attacker's private keys (m1 toward Alice, m2 toward Bob)
# M1, M2            : attacker's public keys (M1 sent to Alice, M2 sent to Bob)
# attacker_alice    : key the attacker shares with Alice (hash of A^m1)
# attacker_bob      : key the attacker shares with Bob (hash of B^m2)
# text              : plaintext message typed by Alice
# encrypted         : ciphertext produced by Alice using alice_key
# intercepted       : plaintext recovered by the attacker using attacker_alice
# forward           : message re-encrypted by the attacker using attacker_bob
# recieved          : message Bob decrypts using bob_key
#
# FUNCTIONS
# key_gen(key)      : SHA-256 of the shared number, gives a 32-byte key
# encrypt(text,key) : XORs each message byte with the key
# decrypt(text,key) : XORs again with the same key and decodes to text
# main()            : runs the normal exchange, the attack and the message flow


# =====================================================================
# SPEECH FOR GUIDE
# =====================================================================
# "Good morning sir/ma'am. My assignment is to implement the Diffie-Hellman
# key exchange and demonstrate a Man-in-the-Middle attack on it.
#
# Diffie-Hellman lets two parties, Alice and Bob, agree on a shared secret over
# an insecure channel without ever sending the secret itself. Its security
# rests on the discrete logarithm problem: knowing g, p and g^a mod p, it is
# very hard to find a.
#
# In my code, p = 23 and g = 5 are the public parameters. I used a small prime
# for demonstration; real systems use 2048-bit primes. Alice and Bob pick random
# private keys a and b using Python's secrets module, which is cryptographically
# secure. Their public keys are A = g^a mod p and B = g^b mod p, computed using
# pow(g, a, p).
#
# First is the normal exchange. Alice computes B^a mod p and Bob computes
# A^b mod p. Both equal g^(ab) mod p, so the program shows that the shared keys
# match. This is correct Diffie-Hellman.
#
# Next is the attack. The attacker generates two private keys, m1 and m2, and
# two public keys, M1 and M2. When Alice sends A towards Bob, the attacker
# replaces it with M2. When Bob sends B towards Alice, the attacker replaces it
# with M1. Neither side can detect this because the exchange has no
# authentication.
#
# Now Alice computes M1^a and the attacker computes A^m1, and these are equal,
# so Alice and the attacker share one key. In the same way, Bob computes M2^b
# and the attacker computes B^m2, so Bob and the attacker share a different
# key. I pass these numbers through key_gen, which uses SHA-256, to get proper
# 32-byte keys. The program prints True for both matches, but Alice and Bob do
# not share any key with each other.
#
# For the message flow, Alice types a message and my encrypt function XORs it
# with her key. The attacker decrypts it using attacker_alice and reads the
# plaintext. He then re-encrypts it with attacker_bob and forwards it. Bob
# decrypts it with bob_key and receives exactly what Alice wrote. So Bob sees a
# normal message, while the attacker has read it and could even have modified
# it.
#
# In conclusion, Diffie-Hellman gives key agreement but not authentication.
# Alice cannot verify that the public key she received really came from Bob.
# The fix is to authenticate public keys using digital signatures or
# certificates, as TLS does, or to use authenticated variants such as the
# Station-to-Station protocol.
#
# Limitations: I used a small prime and XOR encryption for simplicity. A real
# system would use a 2048-bit group and an authenticated cipher like AES-GCM.
# Thank you. I am happy to take questions."


# =====================================================================
# VIVA QUESTIONS AND ANSWERS
# =====================================================================
# Q1. What is Diffie-Hellman used for?
#     Two parties agree on a shared secret key over an insecure channel.
#
# Q2. What is the security of DH based on?
#     The discrete logarithm problem: finding a from g^a mod p is hard.
#
# Q3. Why is the exchange vulnerable to MITM?
#     There is no authentication, so a party cannot verify who owns a public key.
#
# Q4. How many keys does the attacker hold in the MITM attack?
#     Two shared keys: one with Alice and one with Bob. Alice and Bob never
#     share a key with each other.
#
# Q5. Why do you hash the shared secret with SHA-256?
#     The raw secret is a small number (under 23 here). Hashing gives a
#     fixed-length 32-byte key that is better suited as an encryption key.
#
# Q6. Why use secrets instead of random?
#     random is predictable (Mersenne Twister). secrets uses the OS secure
#     random source and is meant for cryptographic use.
#
# Q7. Why is XOR with a repeating key not secure?
#     The key repeats, so patterns leak and known-plaintext attacks recover it.
#     Real systems use AES-GCM.
#
# Q8. Why is p = 23 insecure?
#     The key space is tiny, so an attacker can brute-force a in an instant.
#     Real DH uses 2048-bit or larger primes.
#
# Q9. How can this attack be prevented?
#     Sign the public keys (digital signatures), use certificates (PKI as in
#     TLS), pre-shared keys, or authenticated DH like Station-to-Station.
#
# Q10. Why is pow(g, a, p) used instead of g**a % p?
#     pow with three arguments uses modular exponentiation, which is fast and
#     avoids computing a huge intermediate number.
#
# Q11. Why do both sides get the same secret?
#     (g^b)^a mod p = (g^a)^b mod p = g^(ab) mod p.
#
# Q12. Can the attacker modify the message too?
#     Yes. He can change 'intercepted' before re-encrypting it, and Bob will
#     accept it because there is no integrity check.