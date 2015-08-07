'''
This module generates md5 hashes
'''

import hashlib


class Algorithm:

    def __init__(self):
        self.hash_type = "sha256"
        self.description = "This module generates sha256 hashes"

    def generate(self, cli_object):
        hash_object = getattr(hashlib, "sha256")()
        hash_object.update(cli_object.plaintext)
        return hash_object.hexdigest()
