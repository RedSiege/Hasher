'''
This module generates sha1_crypt hashes
'''

from passlib.hash import sha1_crypt


class Algorithm:

    def __init__(self):
        self.hash_type = "sha1_crypt"
        self.description = "This module generates sha1_crypt hashes"

    def generate(self, cli_object):
        if cli_object.salt is not False:
            if cli_object.rounds is not False:
                generatedhash = sha1_crypt.encrypt(cli_object.plaintext, rounds=int(cli_object.rounds), salt=cli_object.salt)
                return generatedhash
            else:
                generatedhash = sha1_crypt.encrypt(cli_object.plaintext, salt=cli_object.salt)
                return generatedhash
        else:
            if cli_object.rounds is not False:
                generatedhash = sha1_crypt.encrypt(cli_object.plaintext, rounds=int(cli_object.rounds))
                return generatedhash
            else:
                generatedhash = sha1_crypt.encrypt(cli_object.plaintext)
                return generatedhash
        return
