'''
This module generates md5 hashes
'''

from passlib.hash import cisco_pix


class Algorithm:

    def __init__(self):
        self.hash_type = "cisco_pix"
        self.description = "This module generates cisco_pix hashes"

    def generate(self, cli_object):
        generatedhash = cisco_pix.encrypt(cli_object.plaintext, user=cli_object.username)    
        return generatedhash
