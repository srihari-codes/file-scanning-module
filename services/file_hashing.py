import hashlib


class FileHashingService:
    """
    Service for computing file hashes
    """
    
    async def hash_file(self, file_data: bytes) -> str:
        """
        Compute SHA-256 hash of file data
        """
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        
        return sha256_hash