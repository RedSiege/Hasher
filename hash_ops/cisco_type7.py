'''
This module generates md5 hashes
'''

import passlib.hash as hashes


class Algorithm:

    def __init__(self):
        self.hash_type = "cisco_type7"
        self.description = "This module generates cisco type 7 hashes"

    def generate(self, cli_object):
        hashedstring = getattr(hashes, "cisco_type7").encrypt(cli_object.plaintext)
        return hashedstring
