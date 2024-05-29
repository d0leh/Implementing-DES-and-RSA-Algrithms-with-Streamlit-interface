import random
from math import gcd

# Miller-Rabin Primality Test
def is_prime(n, k=128):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    s = n - 1
    r = 0
    while s % 2 == 0:
        s //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x != 1 and x != n - 1:
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
    return True

# Generate a large prime number
def generate_prime_candidate(length):
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length=1024):
    p = 4
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p

# Compute the modular inverse
def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

# Generate RSA key pair
def generate_rsa_keypair(length=1024):
    p = generate_prime_number(length // 2)
    q = generate_prime_number(length // 2)
    while p == q:
        q = generate_prime_number(length // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Common choice for public exponent
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    d = modinv(e, phi)
    return ((e, n), (d, n))

# Encrypt message
def rsa_encrypt(plaintext, public_key):
    e, n = public_key
    plaintext_integers = [ord(char) for char in plaintext]
    ciphertext = [pow(m, e, n) for m in plaintext_integers]
    return ciphertext

# Decrypt message
def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    decrypted_integers = [pow(c, d, n) for c in ciphertext]
    decrypted_message = ''.join(chr(m) for m in decrypted_integers)
    return decrypted_message

# Main function to prompt for plaintext and perform RSA encryption and decryption
def main():
    # Generate RSA key pair
    public_key, private_key = generate_rsa_keypair()
    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")

    # Prompt user for plaintext
    plaintext = input("Enter the plaintext: ")

    # Encrypt the plaintext
    ciphertext = rsa_encrypt(plaintext, public_key)
    print(f"Ciphertext: {ciphertext}")

    # Decrypt the ciphertext
    decrypted_text = rsa_decrypt(ciphertext, private_key)
    print(f"Decrypted: {decrypted_text}")

if __name__ == "__main__":
    main()

