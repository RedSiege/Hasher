'''
This module generates md5 hashes
'''

import passlib.hash as hashes


class Algorithm:

    def __init__(self):
        self.hash_type = "ldap_sha1"
        self.description = "This module generates ldap_sha1 hashes"

    def generate(self, cli_object):
        hashedstring = getattr(hashes, "ldap_sha1").encrypt(cli_object.plaintext)
        return hashedstring
