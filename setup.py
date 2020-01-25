import setuptools
from distutils.tests import test_suite

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="secret-wallet-codimoc",
    version="0.0.1",
    author="codimoc",
    author_email="codimoc@prismoid.uk",
    description="A cloud-based wallet for personal secretwallet",
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
    install_requires = ['boto3','cryptography','python-daemon'],
    entry_points={
        'console_scripts': [
            'secret_wallet = secretwallet.main:main',
            'secret_wallet_conf = secretwallet.main:configure'],
    },
    setup_requires=['pytest-runner'],
    tests_require=['pytest']
)