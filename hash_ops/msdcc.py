'''
This module generates md5 hashes
'''

import sys
from passlib.hash import msdcc


class Algorithm:

    def __init__(self):
        self.hash_type = "msdcc"
        self.description = "This module generates msdcc hashes"

    def generate(self, cli_object):
        if cli_object.username is None:
            print "You must provide a username for msdcc hashes!"
            return "MSDCC hashes require a username"
        generatedhash = msdcc.encrypt(cli_object.plaintext, user=cli_object.username)    
        return generatedhash
