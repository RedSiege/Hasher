'''
This module generates md5 hashes
'''

import passlib.hash as hashes


class Algorithm:

    def __init__(self):
        self.hash_type = "md5_crypt"
        self.description = "This module generates md5_crypt hashes"

    def generate(self, cli_object):

        if not cli_object.salt:
            generated_hash = getattr(hashes, "md5_crypt").encrypt(cli_object.plaintext)
        else:
            generated_hash = getattr(hashes, "md5_crypt").encrypt(cli_object.plaintext, salt=cli_object.salt)

        return generated_hash
