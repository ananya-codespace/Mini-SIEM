# hash chain logic (prev_hash/curr_hash)
import hashlib

# computing hash using the current event's details and previous hash - Tamper-Detection Feature
def compute_hash(event_data, prev_hash):
    # event_data is a 'dict'; no method to directly convert dict->bytes, hence converting to string
    combined = str(event_data) + prev_hash
    # hashlib.sha256() only accepts bytes as input, not plain strings - converted using encode
    curr_hash = hashlib.sha256(combined.encode()).hexdigest()  # converts the internal hash object into a readable hex string
    return curr_hash


"""
* pbkdf2_hmac is designed for password hashing — its whole purpose is to be slow (that 100,000 iterations you used in PyVault) so that if an attacker steals your password 
hashes, brute-forcing them takes forever. That's exactly right for passwords.
* But here, you're not hashing a secret to protect it from brute-forcing — you're creating a fingerprint to detect tampering. You want this to be fast, because you'll be 
computing a hash for every single log event, potentially thousands per second. If you used PBKDF2's 100,000 iterations here, inserting logs would become painfully slow 
for no security benefit — nobody's trying to "crack" a log's hash the way they'd crack a password.
"""