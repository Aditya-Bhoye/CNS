# ---------------------------------------------------------------
# Assignment 7: Digital Signature Algorithm (DSA)
# Aim: Generate and verify digital signatures using DSA and show
#      how they detect modification and wrong keys.
# ---------------------------------------------------------------

# dsa -> used to generate DSA keys (private key can sign, public key can verify)
from cryptography.hazmat.primitives.asymmetric import dsa
# hashes -> gives the SHA-256 hash algorithm; the message is hashed before signing
from cryptography.hazmat.primitives import hashes
# InvalidSignature -> exception raised by the library when verification fails
from cryptography.exceptions import InvalidSignature

# ---------- Step 1: Key generation ----------
def gen_key():
    # Create a 2048-bit DSA private key (kept secret by the sender)
    private_key=dsa.generate_private_key(key_size=2048)
    # Derive the public key from the private key (shared openly) and return both
    return private_key,private_key.public_key()

# ---------- Step 3: Signing ----------
def sign_msg(private_key,msg):
    # encode() converts the text to bytes, SHA-256 hashes it,
    # and the private key signs the hash -> returns the signature (r, s)
    return private_key.sign(msg.encode(),hashes.SHA256())

# ---------- Steps 4 and 5: Verification ----------
def verify_sign(public_key,msg,signature):
    try:
        # Library re-hashes msg and checks it against the signature using the public key
        public_key.verify(signature,msg.encode(),hashes.SHA256())
        # No exception -> signature matches the message and the key
        return True
    except InvalidSignature:
        # Exception -> message changed OR wrong public key
        return False

# ---------- Step 6: Display result ----------
def show_result(label,is_valid):
    # Choose the text according to True/False result of verification
    status="Successful (signature match)" if is_valid else "Failed (signature not match)"
    # {label:<22} left-aligns the label in 22 characters so the output looks neat
    print(f"{label:<22} : {status}")

def main():
    # Step 1: generate the sender's key pair
    private_key,public_key=gen_key()
    # Step 2: accept the message from the user
    msg=input("Enter msg ")
    # Step 3: sign the message with the private key
    sign=sign_msg(private_key,msg)
    # Print the signature in hexadecimal so it is readable
    print("Signature : ",sign.hex())
    # Step 4: verify the original message with the public key -> Successful
    show_result("Original Message : ",verify_sign(public_key,msg,sign))
    # Step 5: tamper with the message by adding "!"
    modifies=msg+"!"
    print("Modified Message  ",modifies)
    # Verify the modified message with the SAME signature -> Failed (integrity)
    show_result("Modifes Message  ",verify_sign(public_key,modifies,sign))
    # Generate a second key pair; "_" ignores its private key, we keep only the public key
    _,other_public_key=gen_key()
    # Verify with the wrong public key -> Failed (authentication)
    show_result("Another public key ",verify_sign(other_public_key,msg,sign))
# Run main() only when this file is executed directly (not when imported)
if __name__=="__main__":
    main()


# ===============================================================
# VARIABLES AND THEIR WORKING
# ===============================================================
# private_key      : DSA private key object. Secret key of the sender, used only for signing.
# public_key       : DSA public key object. Derived from the private key, shared openly,
#                    used only for verifying.
# msg              : String typed by the user. The original message to be signed.
# sign             : Bytes (the pair r, s). Output of signing; sign.hex() makes it printable.
# modifies         : msg + "!". A tampered copy used to test integrity.
# other_public_key : Public key of a different key pair. Acts as an impostor's key
#                    to test authentication.
# signature        : Parameter name inside verify_sign; receives the value of sign.
# is_valid         : True/False returned by verify_sign, used by show_result.
# status           : Text "Successful..." or "Failed..." chosen from is_valid.
# label            : Name of the test printed at the start of each result line.
# _                : Throw-away variable that holds the unused private key of the second pair.


# ===============================================================
# SPEECH TO EXPLAIN TO YOUR GUIDE
# ===============================================================
# Introduction:
# "Good morning sir/ma'am. My assignment is to implement the Digital Signature
#  Algorithm in Python. A digital signature is the electronic equivalent of a
#  handwritten signature. It proves who sent a message and that the message was
#  not changed. I have used the cryptography library for DSA."
#
# Imports:
# "I import dsa for key generation and signing, hashes for SHA-256, and
#  InvalidSignature, which is raised when verification fails."
#
# gen_key():
# "This generates a 2048-bit DSA key pair. The private key is secret with the
#  sender. The public key is derived from it and can be shared with anyone.
#  The function returns both."
#
# sign_msg():
# "This takes the private key and the message. The message is converted to bytes,
#  hashed with SHA-256, and the hash is signed with the private key. The output
#  is the digital signature. Only the private key owner can create it."
#
# verify_sign():
# "This takes the public key, message and signature. The library hashes the
#  received message again and checks it against the signature using the public key.
#  If it matches, I return True. If not, InvalidSignature is raised, which I catch
#  and return False."
#
# show_result():
# "This only prints the result as Successful or Failed. I made it a function so I
#  do not repeat the print statement three times."
#
# main():
# "Step 1, I generate the keys. Step 2, I take the message from the user.
#  Step 3, I sign it and print the signature in hex. Step 4, I verify the original
#  message with the public key, and it is successful. Step 5, I add an exclamation
#  mark to the message and verify it with the same signature. It fails because the
#  hash of the changed message is different. Then I generate another key pair and
#  verify with its public key. That also fails because this key does not match the
#  private key that signed."
#
# Security properties:
# "Integrity: even a one-character change makes verification fail, so tampering is
#  detected.
#  Authentication: only the real sender's public key verifies the signature, so we
#  know who signed it.
#  Non-repudiation: only the sender has the private key, so they cannot later deny
#  signing the message."
#
# Conclusion:
# "So this program shows how DSA generates and verifies signatures, and how it
#  protects a message against modification and impersonation. Thank you."
#
# Likely questions:
# Q. Why SHA-256?  A. Signing the hash is faster than signing the whole message,
#    and any change in the message changes the hash completely.
# Q. Why does the signature differ each time for the same message?
#    A. DSA uses a fresh random value k for every signature; all still verify.
# Q. Can the public key create a signature?  A. No, it can only verify.
# Q. Is non-repudiation guaranteed by the code alone?  A. No. It also depends on
#    the private key staying secret and the public key being tied to the sender's
#    identity, for example through a certificate.