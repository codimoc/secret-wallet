import setuptools
import sys
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass to py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        #import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.pytest_args)
        sys.exit(errno)

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="secret-wallet-codimoc",
    version="0.2.0",
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
    install_requires = ['boto3','cryptography','password_strength','python-daemon','docutils<0.16'],
    entry_points={
        'console_scripts': [
            'secret_wallet = secretwallet.main:main',
            'secret_wallet_conf = secretwallet.main:configure'],
    },
    tests_require=['pytest'],
    cmdclass = {'test': PyTest}, 
    package_data={"tests": ["data/*.json"],
    }
)
