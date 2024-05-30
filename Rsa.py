import streamlit as st
import random
%pip install sympy
from sympy import isprime, mod_inverse

# Function to generate a pair of RSA keys
def generate_keys():
    p = random_prime()
    q = random_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = find_e(phi)
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def random_prime():
    while True:
        num = random.randint(100, 200)
        if isprime(num):
            return num

def find_e(phi):
    e = 3
    while gcd(e, phi) != 1:
        e += 2
    return e

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def encrypt(message, public_key):
    e, n = public_key
    encrypted_message = [pow(ord(char), e, n) for char in message]
    return encrypted_message

def decrypt(encrypted_message, private_key):
    d, n = private_key
    decrypted_message = ''.join([chr(pow(char, d, n)) for char in encrypted_message])
    return decrypted_message

st.title("RSA Encryption Demo")
if st.button("Generate RSA Keys"):
    public_key, private_key = generate_keys()
    st.session_state['public_key'] = public_key
    st.session_state['private_key'] = private_key
    st.write(f"Public Key: {public_key}")
    st.write(f"Private Key: {private_key}")

if 'public_key' in st.session_state:
    message = st.text_input("Enter a message to encrypt:")
    if st.button("Encrypt Message"):
        encrypted_message = encrypt(message, st.session_state['public_key'])
        st.session_state['encrypted_message'] = encrypted_message
        st.write(f"Encrypted Message: {encrypted_message}")

if 'private_key' in st.session_state and 'encrypted_message' in st.session_state:
    if st.button("Decrypt Message"):
        decrypted_message = decrypt(st.session_state['encrypted_message'], st.session_state['private_key'])
        st.write(f"Decrypted Message: {decrypted_message}")