'''
This module generates bcrypt hashes
'''

import sys
import passlib.hash as hashes


class Algorithm:

    def __init__(self):
        self.hash_type = "bcrypt"
        self.description = "This module generates bcrypt hashes"

    def generate(self, cli_object):
        if cli_object.salt is not False:
            if cli_object.rounds is not False:
                try:
                    generatedhash = getattr(hashes, "bcrypt").encrypt(cli_object.plaintext, rounds=cli_object.rounds, salt=cli_object.salt)
                except ValueError:
                    print "Error: BCrypt requres a salt of 22 alphanumeric characters"
                    sys.exit()
                return generatedhash
            else:
                try:
                    generatedhash = getattr(hashes, "bcrypt").encrypt(cli_object.plaintext, salt=cli_object.salt)
                except ValueError:
                    print "Error: BCrypt requres a salt of 22 alphanumeric characters"
                    sys.exit()
                return generatedhash
        else:
            if cli_object.rounds is not False:
                generatedhash = getattr(hashes, "bcrypt").encrypt(cli_object.plaintext, rounds=cli_object.rounds)
                return generatedhash
            else:
                generatedhash = getattr(hashes, "bcrypt").encrypt(cli_object.plaintext)
            return generatedhash
