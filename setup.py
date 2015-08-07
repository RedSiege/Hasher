import io

from setuptools import find_packages, setup


def read(fpath, encoding='utf-8'):
    with io.open(fpath, encoding=encoding) as f:
        return f.read()


setup(
    name = 'hashes',
    version = '1.1.0',
    description = 'A tool to quickly hash plaintext strings, '
                  'or compare hashed values with a plaintext.',
    long_description = read('README.md'),
    url = 'https://github.com/ChrisTruncer/Hasher',
    license = 'GPL 3',
    author = 'Christopher Truncer',

    packages = find_packages(),
    zip_safe = True,
    install_requires = [
        'passlib>=1.6.1',
        'py-bcrypt>=0.4',
        ],
    extras_require = {
        ':python_version=="2.6"': ['argparse'],
        },
    entry_points = {
        'console_scripts': [
            'hashes = hashes.__main__:main',
            ],
        },
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        # TODO check Python 3.2 support of dependencies
        #'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Utilities',
        ],
    )
