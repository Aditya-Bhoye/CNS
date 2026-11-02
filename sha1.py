# =====================================================================
# Assignment 6: SHA-1 Hashing Algorithm
# Aim: To understand cryptographic hash functions, message integrity,
#      and the avalanche effect using SHA-1.
# =====================================================================

# hashlib is Python's built-in library that contains hash functions like SHA-1
import hashlib


# ---------------------------------------------------------------------
# Function 1: sha1(text)
# Takes a normal string and returns its SHA-1 hash as 40 hex characters
# ---------------------------------------------------------------------
def sha1(text):
    # text.encode() converts the string into bytes (hash functions work on bytes)
    # hashlib.sha1(...) calculates the SHA-1 hash
    # .hexdigest() shows the 160-bit result as a 40-character hex string
    return hashlib.sha1(text.encode()).hexdigest()


# ---------------------------------------------------------------------
# Function 2: file_hash(path)
# Takes a file name/path and returns the SHA-1 hash of the whole file
# ---------------------------------------------------------------------
def file_hash(path):
    # Create an empty SHA-1 object; it will be updated piece by piece
    h=hashlib.sha1()
    # Open the file in "rb" mode = read binary, so any file type works
    with open(path,"rb")as file :
        # Read 4096 bytes at a time until read() returns empty bytes (end of file)
        # This way a huge file never has to fit in memory
        for chunk in iter(lambda:file.read(4096),b""):
            # Feed each chunk into the hash object
            h.update(chunk) 
    # After all chunks are added, return the final hash of the full file
    return h.hexdigest()


# ---------------------------------------------------------------------
# Function 3: modified(text)
# Makes a very small change in the message: flips ONE bit of the first character
# ---------------------------------------------------------------------
def modified(text):
    # If the user typed nothing, return "a" so there is something to compare
    if not text:
        return "a"
    # ord() gives the character's number, ^1 (XOR with 1) flips its last bit,
    # chr() converts the number back to a character. Example: 'h'(104) -> 'i'(105)
    first=chr(ord(text[0])^1)
    # New first character + the unchanged rest of the message
    return first+text[1:]


# ---------------------------------------------------------------------
# Function 4: diff_bits(h1, h2)
# Counts how many bits are different between two hex hashes
# ---------------------------------------------------------------------
def diff_bits(h1,h2):
    # Convert both hex strings to big integers (base 16), then XOR them
    # XOR gives 1 where the bits differ and 0 where they are the same
    xor=int(h1,16)^int(h2,16)
    # bin() turns the number into a binary string; counting "1" = differing bits
    return bin(xor).count("1")


# ---------------------------------------------------------------------
# Main function: runs all the steps of the assignment
# ---------------------------------------------------------------------
def main():
    # Step 1: accept a text message from the user
    text=input("Enter text : ")
    # Step 2: generate the SHA-1 hash of the original message
    h1=sha1(text)
    print("Hash text is : ",h1)
    # Step 3: slightly modify the message (one bit of the first character)
    changed=modified(text)
    # Generate the SHA-1 hash of the modified message
    h2=sha1(changed)
    print("Modified text is : ",changed)
    print("Modified text Hash is : ",h2)
    # Step 4: compare both hashes to show the avalanche effect
    # bits = number of differing BITS out of 160
    bits=diff_bits(h1,h2)
    # char = number of differing HEX CHARACTERS out of 40
    # zip() pairs characters of h1 and h2 position by position
    char=sum(a!=b for a,b in zip(h1,h2))
    print("Avalanche Effect ")
    print(f"Differr in hex bits : {bits}/40")
    print(f"Differ in char {char}/160")
    # Step 5: accept a file name and calculate its SHA-1 hash
    path=input("Enter file name ")
    # If the user just presses Enter (empty), the file step is skipped
    if path:
        try:
            print("File hash is : ",file_hash(path))
        except:
            # If the file is missing or the name is wrong, show an error
            raise OSError("Invalid file name ")


# Run main() only when this file is executed directly (not when imported)
if __name__=="__main__":
    main()


# =====================================================================
# VARIABLES AND HOW THEY WORK
# =====================================================================
#
# In sha1(text)
#   text      : the message passed in as a normal string, e.g. "hello".
#               It is converted to bytes, hashed, and the 40-char hex
#               result is returned.
#
# In file_hash(path)
#   path      : the file name or location typed by the user.
#   h         : the SHA-1 object. Starts empty, keeps updating as chunks arrive.
#   file      : the opened file, in binary read mode.
#   chunk     : one 4096-byte piece of the file at a time.
#
# In modified(text)
#   text      : the original message.
#   first     : the first character after flipping one bit ('h' becomes 'i').
#               The function returns first + text[1:].
#
# In diff_bits(h1, h2)
#   h1, h2    : the two hex hashes being compared.
#   xor       : a big number with 1s at every bit position where the
#               two hashes differ.
#
# In main()
#   text      : the message the user typed.
#   h1        : SHA-1 hash of the original text.
#   changed   : the slightly modified text.
#   h2        : SHA-1 hash of the modified text.
#   bits      : number of differing bits (out of 160).
#   char      : number of differing hex characters (out of 40).
#   path      : the file name entered by the user.
#
# Example with "hello":
#   text    = "hello"
#   h1      = aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
#   changed = "iello"
#   h2      = a completely different hash
#   bits    = around 80 (about 50% of 160 bits)


# =====================================================================
# SPEECH FOR GUIDE
# =====================================================================
#
# Good morning, sir/ma'am. Today I will explain my Assignment 6, which is
# the SHA-1 hashing algorithm.
#
# First, what is a hash? A hash function takes any input, like a message or
# a file, and converts it into a fixed-size fingerprint. SHA-1 always gives a
# 160-bit output, which we show as 40 hexadecimal characters. The same input
# always gives the same hash, and we cannot go back from the hash to the
# original input. So it is one-way, and it is not encryption.
#
# My program has four functions.
#
# The first function is sha1. It takes the text, converts it into bytes,
# because hash functions work on bytes, and then uses Python's hashlib to
# calculate the SHA-1 hash and return it in hex form.
#
# The second function is file_hash. It opens the file in binary mode and reads
# it in chunks of 4096 bytes. Each chunk is added to the hash object using
# update. I did this so that even a very large file can be hashed without
# loading it fully into memory. At the end, it returns the hash of the
# complete file.
#
# The third function is modified. It makes a very small change in the message.
# It takes the first character and flips just one bit of it using XOR with 1.
# For example, h becomes i. So the input changes by only a single bit.
#
# The fourth function is diff_bits. It converts both hashes into numbers and
# does XOR between them. Wherever the bits are different, the result has a 1,
# so by counting the 1s I get the number of differing bits.
#
# Now, the main function. First, it takes a message from the user and prints
# its SHA-1 hash. Then it creates the modified message and prints that hash
# too. After that, it compares both hashes. It shows how many of the 160 bits
# are different and how many of the 40 hex characters are different.
#
# This comparison demonstrates the avalanche effect. Even though I changed
# only one bit of the input, the output hash changes completely, and roughly
# half of the bits, around 80 out of 160, are different. That is the property
# of a good hash function, because nobody can predict how the output will
# change from the input change.
#
# Finally, the program asks for a file name and prints that file's SHA-1 hash.
# This is useful for message integrity. If I hash a file before sending it,
# and the receiver hashes it after receiving it, then matching hashes prove
# that the file was not changed. If the file is missing or the name is wrong,
# the program shows an error.
#
# One more point: SHA-1 is good for learning, but it is no longer secure
# against collision attacks. In 2017, Google showed a practical collision,
# called SHAttered. So in real applications, we use SHA-256 or stronger.
#
# That is my assignment. Thank you, and I am happy to answer any questions.