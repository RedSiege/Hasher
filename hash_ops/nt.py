'''
This module generates nt hashes
'''

import passlib.hash as hashes


class Algorithm:

    def __init__(self):
        self.hash_type = "nt"
        self.description = "This module generates NT hashes"

    def generate(self, cli_object):
        nthashed = hashes.nthash.encrypt(cli_object.plaintext)
        return nthashed
