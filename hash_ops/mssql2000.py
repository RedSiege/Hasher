'''
This module generates md5 hashes
'''

import passlib.hash as hashes


class Algorithm:

    def __init__(self):
        self.hash_type = "mssql2000"
        self.description = "This module generates mssql 2000 hashes"

    def generate(self, cli_object):
        hashedstring = getattr(hashes, "mssql2000").encrypt(cli_object.plaintext)
        return hashedstring
