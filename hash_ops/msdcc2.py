'''
This module generates msdcc2 hashes
'''

from passlib.hash import msdcc2


class Algorithm:

    def __init__(self):
        self.hash_type = "msdcc2"
        self.description = "This module generates msdcc2 hashes"

    def generate(self, cli_object):
        if cli_object.username is None:
            print "You must provide a username for msdcc2 hashes!"
            return "MSDCC2 Hashes require a username"
        generatedhash = msdcc2.encrypt(cli_object.plaintext, user=cli_object.username)
        return generatedhash
