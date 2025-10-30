from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
import base64

def generate_key_pair():
    """Generate a new RSA key pair for digital signatures."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Serialize private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key_pem.decode('utf-8'), public_key_pem.decode('utf-8')

def sign_document(file_content, private_key_pem):
    """Sign a document using the provided private key."""
    try:
        # Load the private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None
        )
        
        # Calculate the hash of the file content
        digest = hashes.Hash(hashes.SHA256())
        digest.update(file_content)
        file_hash = digest.finalize()
        
        # Sign the hash
        signature = private_key.sign(
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Convert signature to base64 for storage
        return base64.b64encode(signature).decode('utf-8')
        
    except Exception as e:
        raise Exception(f"Error signing document: {str(e)}")

def verify_signature(file_content, signature, public_key_pem):
    """Verify a document's signature using the provided public key."""
    try:
        # Load the public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8')
        )
        
        # Calculate the hash of the file content
        digest = hashes.Hash(hashes.SHA256())
        digest.update(file_content)
        file_hash = digest.finalize()
        
        # Convert signature from base64
        signature_bytes = base64.b64decode(signature)
        
        # Verify the signature
        try:
            public_key.verify(
                signature_bytes,
                file_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
            
    except Exception as e:
        raise Exception(f"Error verifying signature: {str(e)}")

def get_document_hash(file_content):
    """Calculate the SHA-256 hash of a document."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(file_content)
    return digest.finalize().hex() 