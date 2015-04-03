'''
This module generates md5 hashes
'''

import sys
from passlib.hash import oracle10


class Algorithm:

    def __init__(self):
        self.hash_type = "oracle10"
        self.description = "This module generates oracle10 hashes"

    def generate(self, cli_object):
        if cli_object.username is None:
            print "You must provide a username for oracle10 hashes!"
            sys.exit()
        generatedhash = oracle10.encrypt(cli_object.plaintext, user=cli_object.username)    
        return generatedhash
