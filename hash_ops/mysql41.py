'''
This module generates md5 hashes
'''

import passlib.hash as hashes


class Algorithm:

    def __init__(self):
        self.hash_type = "mysql41"
        self.description = "This module generates mysql41 hashes"

    def generate(self, cli_object):
        hashedstring = getattr(hashes, "mysql41").encrypt(cli_object.plaintext)
        return hashedstring
