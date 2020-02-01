## Introduction

Like many wallet applications, this Python-based utility addresses the requirement of having a single point of access for the large amount
of sensitive information that our social-media presence requires.

If simple and memorable passwords are bad, recycling the same password over and over is evil: with one access compromised, all our secrets and sensitive information are potentially exposed.

Producing and remembering a different complex password for each remote account is hard, and it can quickly become totally unmanageable when passwords need changing frequently.

To store these secrets on paper is not very smart either: a notebook can be safely tucked away in a locked drawer, 
but this is not very helpful when trying to remember the login credentials of a personal banking or private health insurance site, while on holiday abroad.

And if the secret wallet travels with us, it is constantly at risk of being compromised or lost. And with it, all the secrets it contains.

Keeping these secrets on an electronic wallet instead, on a PC, a tablet or a phone, is as safe as the device these secrets are stored on.
Data can be encrypted on a hard drive, but the disk can fail, the phone can be stolen, the tablet forgotten on a plane... And so on.

## Index
*  [motivations](#motivations)
*  [description](#description)
*  [concepts](#concepts)
*  [requirements](#requirements)
*  [installation](#installation)
*  [configuration](#configuration)

## <a id="motivations"></a>Motivations

Fundamentally there are two conflicting requirements: ease of access for the data-owner and protection from unwanted access.
Let's consider these in detail:
* **accessibility**: 
    * The data should be available remotely, from any location. 
    * There should be a single copy of the stored data,
    * The data should be accessible from different devices, of different type. 
    * Data retrieval should be _user-friendly_ and fast,
    * Data retrieved should be in a format that can be cut & pasted into a login form from the same device. 
* **security**:
    * Sensitive data, stored remotely on a server or on the cloud, should be encrypted,
    * There should be no risk of _man in the middle_, _i.e._ data should be transmitted in encrypted format,
    * Data access should be protected by different and independent security tokens,
    * Ideally encryption should happen locally, on trusted devices. Trusted devices can be configured
    by using the same hash-key for encryption (the salt). The generation of this hash-key should be password protected, 
    * The memorable password used as encryption key should be remembered by the owner and not stored,
    * The password used to configure the trusted device should be different from the memorable password used
    to encrypt the data,
    * There should be a third layer of protection on the remote store. 


## <a id="description"></a> The secret wallet, by codimoc, and security considerations

This Python application strives to fulfil these requirements and motivations by:
* Using AWS DynamoDB as the remote store, and relying on the security layer of the Amazon cloud as the third layer of protection, 
* using the Python **cryptography** package for local encryption (on device),
* using the AWS **boto3** package to interact with the remote store
* securing both devices and secrets with independent passwords (the first two layers of protection),
* providing console-based interaction with the secret wallet (for the time being)

Having secured the allowed devices with a configuration password provides safety against misuses of the store once the memorable password is
compromised by accident. For example, if this memorable password is confided to others or guessed, only pre-configured devices can access 
the secrets.

On the other hand, if a device is lost or stolen, the memorable password is still required to access the secrets. The AWS security layer does not help in this case, 
with the AWS secure credentials helpfully located on the compromised device's file system.

## <a id="concepts"></a>Concepts
The basic unit of information stored on the remote DB is a **secret**. 
Each secret is identified by a pair of keys, domain and access:
*   **domain**: the principal context of that secret, _e.g_ the name of a service provider for which we need to store some access credentials,
*   **access**: a sub-context of _domain_; for example if the main domain is a utility provider which provides both a gas and electricity accounts, we might have two secrets with the same domain but different accesses. This separation of domain and access facilitates queries to the DB, since we might want to know all accesses for a given domain, or all the available domains in the wallet.
   
Each secret contains three nullable items of data:
*   **uid**: the user id, or the login credential for that secret. This is stored as an encrypted value,
*   **pwd**: the password required to login in the account with the given user id, _e.g._ the user id and passoword for an online shopping account. 
This passoword-data is also stored encrypted at the source (from tthe local client),
*   **info**: a map of extra information regarding this secret. This meta-data is open-ended, in the sense that anything can go into this dictionary, and it is stored as a json dictionary, with keys unencrypted and values encrypted. For example, if the secret refers to a shopping account, this meta-data could be as follows:

```
    {'telephone' : 1234,
     'delivery-agent' : 'Fast delivery Limited'}
 ```
 
## <a id="requirements"></a>Dependencies and requirements
The **secret wallet** uses the AWS cloud to store the secret information, in particular it relies on the *no-SQL* service AWS *DynomDB*. This is a database with tables that can be defined simply by the declaration of one or two primary keys. The remaining part of the schema can change and grow and it is data driven, *i.e.* it depends on the format of the records we want to store. The advantage of this storage solution are:
*   It is a remote storage widely available on the Amazon cloud.
*   It is simple to use and create new tables,
*   And mainly it is available in the [AWS Free Tier](https://aws.amazon.com/free/?all-free-tier.sort-by=item.additionalFields.SortRank&all-free-tier.sort-order=asc) package that Amazon offers as an entry point into their echo-system.

In order to use the **secret wallet** it is therefore required to use or create a new Amazon AWS account. This can be done quickly and easily from the [AWS Free Tier](https://aws.amazon.com/free/?all-free-tier.sort-by=item.additionalFields.SortRank&all-free-tier.sort-order=asc) page. Once the account has been created, the three pieces of information required in order to use this app are:
*   **aws_access_key_id**: to identify the account
*   **aws_secret_access_key**: which can be generated after logging into the account; this key can be regenerated several times
*   **region**: the physical location of the server, possibly close to the location of usage.

These three pieces of information should be noted down when creating the account or copied into the clipboard or on a file. They will be required later, when [configuring](#configuration) the **secret wallet**.

It should be noted that the initial AWS keys, produced when creating the new account, are root credentials for that account. It is safer, once logged into this new AWS account, to create some IAM roles with limited access, for example a programmatic user, and to use these credentials instead. Instruction on how to do this can be found [here](https://aws.amazon.com/iam/).

## <a id="installation"></a>Installation
The **secret wallet** is installed in the usual manner, as any other python package, and requires a minimum python version of 3.6.
The installation is done with:

```python
pip install secret-wallet-codimoc 
```
This will first install all the dependencies from other python packages and will produce two new executable scripts:
*   **secret_wallet** for the command line management of the secret wallet and
*   **secret_wallet_conf** for the first time configuration as described below

## <a id="configuration"></a>First time configuration
  
## <a id="passwords"></a>Password strength
 
## <a id="syntax"></a>Syntax

## <a id="usage"></a>Usage

## <a id="session"></a>The secret-wallet session

## <a id="customisation"></a>Manual customisation of parameters

## <a id="reconfiguration"></a>Reconfiguration

## <a id="work"></a>Work in progress

## <a id="help"></a>Help needed

## <a id="faq"></a>FAQ