'''
This module generates md5 hashes
'''

import passlib.hash as hashes


class Algorithm:

    def __init__(self):
        self.hash_type = "oracle11"
        self.description = "This module generates Oracle 11 hashes"

    def generate(self, cli_object):
        hashedstring = getattr(hashes, "oracle11").encrypt(cli_object.plaintext)
        return hashedstring
