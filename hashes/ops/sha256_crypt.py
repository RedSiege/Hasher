'''
This module generates sha256_crypt hashes
'''

from hashes.common import helpers
from passlib.hash import sha256_crypt


class Algorithm:

    def __init__(self):
        self.hash_type = "sha256_crypt"
        self.description = "This module generates sha256_crypt hashes"

    def generate(self, cli_object):
        if cli_object.salt is not False:
            if cli_object.rounds is not False:
                try:
                    generatedhash = sha256_crypt.encrypt(cli_object.plaintext, rounds=int(cli_object.rounds), salt=cli_object.salt)
                    return generatedhash
                except ValueError:
                    print helpers.color("Sha256_crypt and sha512_crypt require at least 1000 rounds.", warning=True)
                    print helpers.color("[*] Running with default of 80000 rounds.", warning=True)
                    generatedhash = sha256_crypt.encrypt(cli_object.plaintext, salt=cli_object.salt)
                    return generatedhash
            else:
                generatedhash = sha256_crypt.encrypt(cli_object.plaintext, salt=cli_object.salt)
                return generatedhash
        else:
            if cli_object.rounds is not False:
                try:
                    generatedhash = sha256_crypt.encrypt(cli_object.plaintext, rounds=int(cli_object.rounds))
                    return generatedhash
                except ValueError:
                    print helpers.color("[*] Warning: Sha256_crypt and sha512_crypt require at least 1000 rounds.", warning=True)
                    print helpers.color("[*] Running with default of 80000 rounds.", warning=True)
                    generatedhash = sha256_crypt.encrypt(cli_object.plaintext)
                    return generatedhash
            else:
                generatedhash = sha256_crypt.encrypt(cli_object.plaintext)
                return generatedhash
        return
