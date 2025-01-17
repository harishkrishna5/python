import hashlib
import hmac
import base64

def calculate_secret_hash(username, client_id, client_secret):
    # Prepare the message to hash (username + client_id)
    message = username + client_id
    
    # Generate the HMACSHA256 hash using the client secret
    secret_hash = hmac.new(
        bytes(client_secret, 'utf-8'),
        bytes(message, 'utf-8'),
        hashlib.sha256
    )
    
    # Base64 encode the hash
    secret_hash_b64 = base64.b64encode(secret_hash.digest()).decode()

    return secret_hash_b64

# Given values
username = "myuser"
client_id = "4m36bap2d5600lc95r3kobm84t"
client_secret = "uq1l9or6078mmdvkvclkub2d25fd22gn1unf7rap2mbdcfllusq"

# Calculate the SECRET_HASH
secret_hash = calculate_secret_hash(username, client_id, client_secret)

# Output the SECRET_HASH
print("SECRET_HASH:", secret_hash)
