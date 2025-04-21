import hashlib
import itertools
import logging
from typing import Dict, Optional, List
import os


class PasswordCracker:
    def __init__(self):
        self.threads = 4
        self.wordlist = None
        self.cracking = False
        self.found_password = None
        self.hash_type = None
        self.hash_functions = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512,
        }

    def validate_hash(self, hash_str: str) -> Optional[str]:
        """Validate hash format and determine hash type."""
        hash_lengths = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

        # Remove any whitespace
        hash_str = hash_str.strip()

        # Check if hash length matches known hash types
        hash_type = hash_lengths.get(len(hash_str))
        if not hash_type:
            return None

        # Verify hash contains only hexadecimal characters
        try:
            int(hash_str, 16)
            return hash_type
        except ValueError:
            return None

    def validate_wordlist(self, wordlist_path: str) -> bool:
        """Validate wordlist file."""
        try:
            if not os.path.exists(wordlist_path):
                return False
            if not os.path.isfile(wordlist_path):
                return False
            if os.path.getsize(wordlist_path) == 0:
                return False
            return True
        except:
            return False

    def load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load wordlist from file."""
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logging.error(f"Error loading wordlist: {str(e)}")
            return []

    def crack_hash(self, hash_str: str, word: str) -> bool:
        """Try to crack hash with a word."""
        try:
            hash_func = self.hash_functions[self.hash_type]
            hashed_word = hash_func(word.encode()).hexdigest()
            return hashed_word == hash_str.lower()
        except Exception as e:
            logging.error(f"Error cracking hash: {str(e)}")
            return False

    def worker(self, hash_str: str) -> None:
        """Worker thread for password cracking."""
        while not self.wordlist.empty() and self.cracking and not self.found_password:
            word = self.wordlist.get()
            if self.crack_hash(hash_str, word):
                self.found_password = word
                self.cracking = False
            self.wordlist.task_done()

    def crack(self, hash_str: str, wordlist_path: str, hash_type: str = "md5") -> Dict:
        try:
            # Validate hash type
            if hash_type.lower() not in self.hash_functions:
                return {
                    "error": f"Unsupported hash type: {hash_type}. Supported types: {', '.join(self.hash_functions.keys())}"
                }

            # Validate wordlist file
            if not os.path.exists(wordlist_path):
                return {"error": f"Wordlist file not found: {wordlist_path}"}

            # Get hash function
            hash_func = self.hash_functions[hash_type.lower()]

            # Try to crack the hash
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    password = line.strip()
                    if not password:
                        continue

                    # Hash the password
                    hashed = hash_func(password.encode()).hexdigest()

                    # Check if hash matches
                    if hashed.lower() == hash_str.lower():
                        return {
                            "success": True,
                            "hash": hash_str,
                            "hash_type": hash_type,
                            "password": password,
                        }

            return {
                "success": False,
                "hash": hash_str,
                "hash_type": hash_type,
                "message": "Password not found in wordlist",
            }

        except Exception as e:
            logging.error(f"Error cracking password: {str(e)}")
            return {"error": f"Cracking failed: {str(e)}"}

    def generate_brute_force(self, length: int, charset: str = None) -> List[str]:
        """Generate brute force combinations."""
        if charset is None:
            charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

        return [
            "".join(candidate)
            for candidate in itertools.product(charset, repeat=length)
        ]

    def brute_force(
        self, hash_str: str, max_length: int = 4, charset: str = None
    ) -> Dict:
        """Brute force password cracking."""
        # Reset results
        self.found_password = None
        self.cracking = True

        # Validate inputs
        self.hash_type = self.validate_hash(hash_str)
        if not self.hash_type:
            raise ValueError("Invalid hash format")

        # Try different lengths
        for length in range(1, max_length + 1):
            if not self.cracking:
                break

            # Generate combinations
            combinations = self.generate_brute_force(length, charset)

            # Try each combination
            for word in combinations:
                if not self.cracking:
                    break
                if self.crack_hash(hash_str, word):
                    self.found_password = word
                    self.cracking = False
                    break

        # Return results
        return {
            "hash": hash_str,
            "hash_type": self.hash_type,
            "found": self.found_password is not None,
            "password": self.found_password,
            "method": "brute_force",
        }

    def generate_example_wordlist(self, output_path: str) -> bool:
        try:
            example_words = [
                "password",
                "123456",
                "qwerty",
                "admin",
                "letmein",
                "welcome",
                "monkey",
                "dragon",
                "baseball",
                "football",
            ]

            with open(output_path, "w") as f:
                for word in example_words:
                    f.write(f"{word}\n")

            return True
        except Exception as e:
            logging.error(f"Error generating example wordlist: {str(e)}")
            return False

    def get_hash_examples(self) -> Dict[str, str]:
        """Get example hashes for testing."""
        return {
            "md5": "5f4dcc3b5aa765d61d8327deb882cf99",  # password
            "sha1": "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",  # password
            "sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",  # password
            "sha512": "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049c46db5821b4e7f6fb1b86e3f6b5c5c5c5c5c5c5c5c5c5c",  # password
        }
