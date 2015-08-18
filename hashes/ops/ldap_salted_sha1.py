'''
This module generates md5 hashes
'''

import passlib.hash as hashes


class Algorithm:

    def __init__(self):
        self.hash_type = "ldap_salted_sha1"
        self.description = "This module generates ldap_salted_sha1 hashes"

    def generate(self, cli_object):

        if not cli_object.salt:
            generated_hash = getattr(hashes, "ldap_salted_sha1").encrypt(cli_object.plaintext)
        else:
            generated_hash = getattr(hashes, "ldap_salted_sha1").encrypt(cli_object.plaintext, salt=cli_object.salt)

        return generated_hash
