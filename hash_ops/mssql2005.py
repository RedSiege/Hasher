'''
This module generates md5 hashes
'''

import passlib.hash as hashes


class Algorithm:

    def __init__(self):
        self.hash_type = "mssql2005"
        self.description = "This module generates mssql 2005 hashes"

    def generate(self, cli_object):
        hashedstring = getattr(hashes, "mssql2005").encrypt(cli_object.plaintext)
        return hashedstring
