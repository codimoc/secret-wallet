import sys

import setuptools
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass to py.test")]

    #This is required to initialise/declare the variables in the associated class
    #Without this the self.pytest_args would not be there
    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args=list() #it is only used to declare the variable

    #This set the initial/default value of the class variable (self.test_args)
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        #How to pass parameters to pytest, e.g. running all test with the word 'save' in it
        #pass a space separated string of tokens: >>python3 setup.py test -a '-k save'
        #where -a or --pytest-args is the command option
        import pytest
        errno = pytest.main(self.pytest_args.split(' '))
        sys.exit(errno)
        
        

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="secret-wallet-codimoc",
    version="0.6.1",
    author="codimoc",
    author_email="codimoc@prismoid.uk",
    description="A cloud-based wallet for personal secrets",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/codimoc/secret-wallet",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires = ['boto3',
                        'cryptography',
                        'password_strength',
                        'python-daemon',
                        'docutils<0.16',
                        'pyreadline'],
    entry_points={
        'console_scripts': [
            'secret_wallet = secretwallet.main:main',
            'secret_wallet_shell = secretwallet.main:shell',
            'secret_wallet_conf = secretwallet.main:configure'],
    },
    tests_require=['pytest'],
    cmdclass = {'test': PyTest},
    package_data={"tests": ["data/*.json"],
    }
)
