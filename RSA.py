import random
import math
import hashlib
from typing import Tuple, List


def is_prime(n: int, k: int = 5) -> bool:
    """
    Miller-Rabin primality test
    
    Args:
        n: Number to test for primality
        k: Number of test rounds
    
    Returns:
        bool: True if probably prime, False if definitely composite
    """
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True
    
    # Find r and d such that n-1 = 2^r * d, d is odd
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    
    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
            
    return True


def generate_prime(bits: int) -> int:
    """
    Generate a random prime number with specified bit length
    
    Args:
        bits: Bit length of the prime number
    
    Returns:
        int: A prime number
    """
    while True:
        # Generate random odd integer with specified bit length
        p = random.getrandbits(bits) | (1 << bits - 1) | 1
        if is_prime(p):
            return p


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm to find gcd and coefficients
    
    Args:
        a, b: Integers for GCD calculation
    
    Returns:
        Tuple[int, int, int]: (gcd, x, y) where ax + by = gcd
    """
    if a == 0:
        return b, 0, 1
    
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd, x, y


def mod_inverse(e: int, phi: int) -> int:
    """
    Find the modular multiplicative inverse of e mod phi
    
    Args:
        e: Integer to find inverse for
        phi: Modulus
    
    Returns:
        int: Modular multiplicative inverse
    """
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return x % phi


def generate_keypair(bits: int = 1024) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Generate RSA public/private key pairs
    
    Args:
        bits: Bit length for each prime number
    
    Returns:
        Tuple[Tuple[int, int], Tuple[int, int]]: ((e, n), (d, n)) - (public_key, private_key)
    """
    # Generate two distinct primes
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)
    
    # Compute n and Euler's totient function φ(n)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    # Choose e: 1 < e < φ(n) and gcd(e, φ(n)) = 1
    # 65537 is a common choice for e
    e = 65537
    while math.gcd(e, phi_n) != 1:
        e += 2
    
    # Calculate d: modular multiplicative inverse of e mod φ(n)
    d = mod_inverse(e, phi_n)
    
    # Public key: (e, n), Private key: (d, n)
    return ((e, n), (d, n))


def encrypt(message: int, public_key: Tuple[int, int]) -> int:
    """
    Encrypt a message using RSA
    
    Args:
        message: Integer representation of the message
        public_key: Tuple containing (e, n)
    
    Returns:
        int: Encrypted message
    """
    e, n = public_key
    if message >= n:
        raise ValueError("Message is too large for the key size")
    
    # c = m^e mod n
    return pow(message, e, n)


def decrypt(ciphertext: int, private_key: Tuple[int, int]) -> int:
    """
    Decrypt a message using RSA
    
    Args:
        ciphertext: Encrypted message
        private_key: Tuple containing (d, n)
    
    Returns:
        int: Decrypted message
    """
    d, n = private_key
    
    # m = c^d mod n
    return pow(ciphertext, d, n)


def string_to_int(message: str) -> int:
    """
    Convert a string to integer
    
    Args:
        message: Input string
    
    Returns:
        int: Integer representation of the string
    """
    return int.from_bytes(message.encode('utf-8'), byteorder='big')


def int_to_string(value: int) -> str:
    """
    Convert an integer back to string
    
    Args:
        value: Integer value
    
    Returns:
        str: String representation
    """
    byte_length = (value.bit_length() + 7) // 8
    return value.to_bytes(byte_length, byteorder='big').decode('utf-8', errors='ignore')


def encrypt_string(message: str, public_key: Tuple[int, int]) -> List[int]:
    """
    Encrypt a string message using RSA
    
    Args:
        message: String to encrypt
        public_key: Public key tuple (e, n)
    
    Returns:
        List[int]: List of encrypted chunks
    """
    _, n = public_key
    # Calculate maximum bytes per chunk
    max_bytes = (n.bit_length() - 1) // 8
    
    # Convert string to bytes
    message_bytes = message.encode('utf-8')
    
    # Split message into chunks
    chunks = [message_bytes[i:i+max_bytes] for i in range(0, len(message_bytes), max_bytes)]
    
    # Encrypt each chunk
    encrypted_chunks = []
    for chunk in chunks:
        chunk_int = int.from_bytes(chunk, byteorder='big')
        encrypted_chunks.append(encrypt(chunk_int, public_key))
    
    return encrypted_chunks


def decrypt_string(ciphertext_chunks: List[int], private_key: Tuple[int, int]) -> str:
    """
    Decrypt a list of encrypted chunks back to string
    
    Args:
        ciphertext_chunks: List of encrypted chunks
        private_key: Private key tuple (d, n)
    
    Returns:
        str: Decrypted string
    """
    decrypted_bytes = b''
    
    for chunk in ciphertext_chunks:
        decrypted_chunk = decrypt(chunk, private_key)
        chunk_bytes = decrypted_chunk.to_bytes((decrypted_chunk.bit_length() + 7) // 8, byteorder='big')
        decrypted_bytes += chunk_bytes
    
    return decrypted_bytes.decode('utf-8')


def hash_message(message: str) -> int:
    """
    Create a hash of the message and convert to integer
    
    Args:
        message: Message to hash
    
    Returns:
        int: Integer representation of hash
    """
    hash_obj = hashlib.sha256(message.encode('utf-8'))
    hash_digest = hash_obj.digest()
    return int.from_bytes(hash_digest, byteorder='big')


def sign_message(message: str, private_key: Tuple[int, int]) -> int:
    """
    Create a digital signature for a message using RSA
    
    Args:
        message: Message to sign
        private_key: Private key tuple (d, n)
    
    Returns:
        int: Digital signature
    """
    # Hash the message
    message_hash = hash_message(message)
    d, n = private_key
    
    # If hash is larger than n, truncate it
    message_hash = message_hash % n
    
    # Sign the hash: signature = hash^d mod n
    signature = pow(message_hash, d, n)
    return signature


def verify_signature(message: str, signature: int, public_key: Tuple[int, int]) -> bool:
    """
    Verify a digital signature for a message using RSA
    
    Args:
        message: Original message
        signature: Digital signature to verify
        public_key: Public key tuple (e, n)
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    # Hash the message
    message_hash = hash_message(message)
    e, n = public_key
    
    # If hash is larger than n, truncate it
    message_hash = message_hash % n
    
    # Verify the signature: hash == signature^e mod n
    hash_from_signature = pow(signature, e, n)
    return message_hash == hash_from_signature


def demonstrate_rsa():
    """
    Demonstrate RSA encryption, decryption, and digital signatures
    """
    print("\n" + "="*50)
    print("  RSA ENCRYPTION & DIGITAL SIGNATURE DEMONSTRATION")
    print("="*50 + "\n")
    
    # Generate keypair
    print("Generating RSA keypair...")
    public_key, private_key = generate_keypair(bits=1024)
    e, n = public_key
    d, _ = private_key
    
    print(f"\nPublic key (e, n):")
    print(f"  e: {e}")
    print(f"  n: {n}\n")
    
    print(f"Private key (d, n):")
    print(f"  d: {d}")
    print(f"  n: {n}\n")
    
    # Test with numeric message
    original_num = 42
    print(f"[NUMERIC MESSAGE ENCRYPTION]")
    print(f"  Original message: {original_num}")
    
    encrypted_num = encrypt(original_num, public_key)
    print(f"  Encrypted: {encrypted_num}")
    
    decrypted_num = decrypt(encrypted_num, private_key)
    print(f"  Decrypted: {decrypted_num}")
    print(f"  Verification: {'Success' if original_num == decrypted_num else 'Failed'}\n")
    
    # Test with text message
    original_text = "Hello, RSA encryption and digital signatures!"
    print(f"[TEXT MESSAGE ENCRYPTION]")
    print(f"  Original message: '{original_text}'")
    
    encrypted_chunks = encrypt_string(original_text, public_key)
    print(f"  Encrypted (first chunk): {encrypted_chunks[0]}")
    print(f"  Number of chunks: {len(encrypted_chunks)}")
    
    decrypted_text = decrypt_string(encrypted_chunks, private_key)
    print(f"  Decrypted: '{decrypted_text}'")
    print(f"  Verification: {'Success' if original_text == decrypted_text else 'Failed'}\n")
    
    # Test digital signatures
    print(f"[DIGITAL SIGNATURE DEMONSTRATION]")
    print(f"  Original message: '{original_text}'")
    
    # Sign the message
    signature = sign_message(original_text, private_key)
    print(f"  Message signature: {signature}")
    
    # Verify the original message with signature
    is_valid = verify_signature(original_text, signature, public_key)
    print(f"  Signature verification: {'Valid signature' if is_valid else 'Invalid signature'}")
    
    # Tamper with the message and verify again
    tampered_message = original_text + " [Tampered]"
    print(f"\n  Tampered message: '{tampered_message}'")
    is_valid = verify_signature(tampered_message, signature, public_key)
    print(f"  Tampered message verification: {'Valid signature' if is_valid else 'Invalid signature - Message was tampered!'}")
    
    print("\n" + "="*50)
    print("  DEMONSTRATION COMPLETE")
    print("="*50 + "\n")


if __name__ == "__main__":
    demonstrate_rsa()