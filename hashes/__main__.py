#!/usr/bin/env python

'''
This is an update to Hasher, something I wrote a long time ago.
Ideally this will make it easier to use, and to add new hashtypes.
'''

from hashes.common import helpers
from hashes.common import orchestra


def main():
    # print the title screen for the first "run"
    helpers.print_header()

    # instantiate the orchesta object and call the main menubar
    the_conductor = orchestra.Conductor()
    the_conductor.menu_system()


if __name__ == '__main__':
    main()
