# =====================================================================
# Assignment 4: Custom Encryption and Decryption Algorithm
# Aim: To understand symmetric encryption by building a custom cipher
# using SHA-256 + XOR (educational only, not a replacement for AES).
# =====================================================================
#
# =====================================================================


# ---------- Imports ----------
import hmac        # makes the tamper-proof tag (HMAC)
import hashlib     # SHA-256 for the key and the keystream
import secrets     # cryptographically secure random bytes (for the nonce)


# ---------- Keystream generator ----------
# Builds 'size' bytes of random-looking data from key + nonce.
# SHA-256 gives only 32 bytes per call, so we loop with a counter.
def key_stream(key,nonce,size):
    result=b""                 # empty bytes; the keystream is built here
    counter=0                  # round number, makes every block different
    while len(result)<size:    # keep going until we have enough bytes
        # hash(key + nonce + counter) -> 32 new bytes, added to result
        result+=hashlib.sha256(key+nonce+counter.to_bytes(4,'big')).digest()
        counter+=1             # next round uses a different counter
    return result[:size]       # cut extra bytes, return exactly 'size'


# ---------- Encryption ----------
def encrypt(text,password):
    # Password -> 32-byte key using SHA-256 (assignment requirement 2)
    key=hashlib.sha256(password.encode()).digest()
    # Fresh random 16-byte nonce, so the keystream is never reused
    nonce=secrets.token_bytes(16)
    # Convert message from str to bytes, because XOR works on bytes
    data=text.encode()
    # Keystream exactly as long as the message
    stream=key_stream(key,nonce,len(data))
    # XOR each message byte with the matching keystream byte
    cipher=bytes(a^b for a,b in zip(data,stream))
    # HMAC tag over nonce + cipher: detects wrong password / tampering
    tag=hmac.new(key,nonce+cipher,hashlib.sha256).digest()
    # Pack as nonce(16) + tag(32) + cipher(n), then convert to hex text
    return (nonce+tag+cipher).hex()


# ---------- Decryption ----------
def decrypt(text,password):
    # Rebuild the key; same password gives the same key
    key=hashlib.sha256(password.encode()).digest()
    # Hex text -> bytes (fromhex needs a str, so no .encode() here)
    raw=bytes.fromhex(text)
    # Nonce (16) + tag (32) = 48 bytes minimum, else data is invalid
    if len(raw)<48:
        raise ValueError("Invalid cipher ")
    # Split into the 3 parts, reverse of how encrypt() packed them
    nonce,tag,cipher=raw[:16],raw[16:48],raw[48:]
    # Recalculate the tag the way it should be
    expected=hmac.new(key,nonce+cipher,hashlib.sha256).digest()
    # Constant-time comparison (avoids timing attacks); verify BEFORE decrypting
    if not hmac.compare_digest(tag,expected):
        raise ValueError("Wrong password or Invalid cipher ")
    # Same key + same nonce = same keystream as during encryption
    stream=key_stream(key,nonce,len(cipher))
    # XOR again to cancel the keystream, then bytes -> str
    return bytes(a^b for a,b in zip(cipher,stream)).decode()


# ---------- Main program ----------
def main():
    text=input("Enter text ")              # requirement 1: plaintext
    password=input("Enter password ")      # requirement 1: password
    print("Original text : ",text)
    encrypted=encrypt(text,password)       # requirement 3: encrypt
    decrypted=decrypt(encrypted,password)  # requirement 4: decrypt
    print("Encrypted text : ",encrypted)
    print("Decrypted text : ",decrypted)   # requirement 5: should match original


# Run main() only when this file is executed directly
if __name__=="__main__":
    main()


# =====================================================================
# ---------------------------------------------------------------------
# VARIABLES AND HOW THEY WORK
# ---------------------------------------------------------------------
#
# key_stream(key, nonce, size)
#   key      (bytes, 32) : secret key made from the password; makes the
#                          keystream depend on the password
#   nonce    (bytes, 16) : random value, new for every encryption; makes
#                          the keystream different each time
#   size     (int)       : number of keystream bytes needed (= message
#                          length); tells the loop when to stop
#   result   (bytes)     : the keystream being built; starts as b"" and
#                          32 bytes are added every round
#   counter  (int)       : round number 0, 1, 2...; changes the hash
#                          input each round so blocks never repeat
#
# encrypt(text, password)
#   text     (str)       : plaintext message
#   password (str)       : password typed by the user
#   key      (bytes, 32) : SHA-256 of the password; used for keystream
#                          and for the HMAC tag
#   nonce    (bytes, 16) : random bytes from `secrets`; stored in output
#   data     (bytes)     : message converted with .encode()
#   stream   (bytes)     : keystream, same length as data (the "mask")
#   cipher   (bytes)     : data XOR stream = encrypted message
#   tag      (bytes, 32) : HMAC of nonce + cipher; detects wrong
#                          password or tampering
#   a, b     (int)       : one byte of data and one byte of stream
#   returns  (str)       : (nonce + tag + cipher) as a hex string
#
# decrypt(text, password)
#   text     (str)       : the hex encrypted string
#   password (str)       : must match the password used to encrypt
#   key      (bytes, 32) : SHA-256 of the password; a wrong password
#                          gives a different key, so tag check fails
#   raw      (bytes)     : hex converted back to bytes
#   nonce    (bytes, 16) : first 16 bytes of raw
#   tag      (bytes, 32) : bytes 16 to 47 of raw (stored seal)
#   cipher   (bytes)     : bytes 48 onward (encrypted message)
#   expected (bytes, 32) : tag recalculated with our key, compared
#                          with the stored tag
#   stream   (bytes)     : rebuilt keystream (same key + nonce)
#   a, b     (int)       : one cipher byte and one stream byte
#   returns  (str)       : the original message
#
# main()
#   text      : plaintext typed by the user
#   password  : password typed by the user
#   encrypted : hex ciphertext returned by encrypt()
#   decrypted : plaintext recovered by decrypt(); should equal text
#
# Constants
#   16 = nonce length in bytes
#   32 = SHA-256 output size (also the tag size)
#   48 = 16 + 32, minimum valid length (nonce + tag)
#   4  = number of bytes used to store the counter
#
# Packet layout:  | nonce (16) | tag (32) | cipher (n bytes) |
# =====================================================================


# =====================================================================
# SPEECH FOR THE GUIDE
# =====================================================================
#
# Good morning, sir/madam. Today I will explain my Assignment 4, a
# custom encryption and decryption algorithm built in Python.
#
# The aim is to understand symmetric encryption, where the same secret
# is used to lock and unlock data. I built a small cipher using SHA-256
# and XOR. The program takes two inputs: a plaintext message and a
# password.
#
# First, the encrypt function converts the password into a key using
# SHA-256. SHA-256 always gives a fixed 32-byte output, so any password
# becomes a proper key, and the same password always gives the same key.
#
# Second, it generates a random 16-byte nonce, which means "number used
# once". It is different every time, so even the same message encrypts
# to a different output. This prevents the keystream reuse attack, the
# biggest weakness of XOR-based encryption.
#
# Third, my key_stream function builds the keystream. SHA-256 gives only
# 32 bytes at a time, but a message can be longer, so I hash the key,
# the nonce and a counter together, and increase the counter every round
# until the keystream is as long as the message. This is similar to
# counter mode in standard ciphers.
#
# Fourth is the actual encryption. I convert the message into bytes and
# XOR each byte with the matching keystream byte to get the ciphertext.
# XOR has a useful property: applying it twice with the same value gives
# back the original, so decryption uses the same operation.
#
# Fifth, I add an HMAC tag, a tamper-proof seal calculated from the key,
# nonce and ciphertext. If someone changes the ciphertext or uses a wrong
# password, the tag will not match.
#
# The final output is nonce, tag and ciphertext joined together and
# converted to hex so it is readable.
#
# Now decryption. The decrypt function converts the hex back to bytes and
# splits it into nonce, tag and ciphertext. It rebuilds the key from the
# password and recalculates the tag. If the tags do not match, it stops
# with an error, so unverified data is never decrypted. If they match, it
# rebuilds the same keystream and XORs it with the ciphertext to get the
# original message.
#
# In main, the program prints the original text, the encrypted text and
# the decrypted text, which shows that the decrypted message matches the
# original.
#
# For safe practice, I used the secrets module for the nonce because it
# is cryptographically secure, and compare_digest for comparing tags to
# avoid timing attacks.
#
# Finally, the limitations. This is an educational scheme, not a
# replacement for AES. The same key is used for both the keystream and
# the HMAC, and a single SHA-256 of the password is fast to brute-force.
# Real systems use key derivation functions like PBKDF2 or scrypt with a
# salt, and standard algorithms like AES-GCM.
#
# To conclude, this assignment helped me understand how keys, nonces,
# keystreams, XOR and authentication work together in symmetric
# encryption. Thank you.
# =====================================================================