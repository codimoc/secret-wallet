Like many wallet applications, this Python-based utility addresses the requirement of having a single point of access for the large amount
of sensitive information that our social-media presence produces.

If simple and memorable passwords are bad, recycling the same password over and over is evil: with one access compromised, all our secrets and sensitive information are potentially exposed.

Producing and remembering a different complex password for each remote account is hard, and it can quickly become totally unmanageable when passwords need changing frequently.

To store these secrets on paper is not very smart either: a notebook can be safely tucked away in a locked drawer, 
but this is not very helpful when trying to remember the login credentials of a personal banking or private health insurance site, while on holiday abroad.

And if the secret wallet travels with us, it is constantly at risk of being compromised or lost. And with it, all the secrets it contains.

Keeping these secrets on an electronic wallet instead, on a PC, a tablet or a phone, is as safe as the device these secrets are stored on.
Data can be encrypted on a hard drive, but the disk can fail, the phone can be stolen, the tablet forgotten on a plane... And so on.

## Motivations

Fundamentally there are two conflicting requirements: ease of access for the data-owner and protection from unwanted access.
Let's consider these in detail:
* **accessibility**: 
    * The data should be available remotely, from any location. 
    * There should be a single copy of the stored data,
    * The data should be accessible from different devices, of different type. 
    * Data retrieval should be _user-friendly_ and fast,
    * Data retrieved should be in a format that can be cut & pasted into a login form accessed from the same device. 
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


## The secret wallet, by codimoc, and security considerations

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

## Concepts
The basic unit of information stored on the remote DB is a **secret**. 
Each secret is identified by a pair of keys, domain and access:
*   **domain**: the principal context of that secret, _e.g_ the name of a service provider for which we need to store some access credentials,
*   **access**: a sub-context of _domain_; for example if the main domain is a utility provider which provides both a gas and electricity accounts, we might have two secrets with the same domain but different accesses. This separation of domain and access facilitates queries to the DB, since we might want to know all accesses for a given domain, or all the available domains in the wallet.
   
Each secret contains three nullable items of data:
*   **uid**: the user id, or the login credential for that secret. This is stored as an encrypted value,
*   **pwd**: the password required to login in the account with the given user id, _e.g._ the UID and pwd of an online shopping account. 
This data is also stored as an encrypted value,
*   **info**: a map of extra information regarding this secret. This meta-data is open-ended, in the sense that anything can go into this dictionary, and it is stored as a json dictionary. For example, if the secret refers to a shopping account, this meta-data could be as follows:

```
    {'telephone' : 1234,
     'delivery-agent' : 'Fast delivery Limited'}
 ```
 This data is currently stored without the first two layers of encryption and relies only on the AWS security layer. It might be encrypted in
 future releases.
 
  
## Syntax

## Usage

## First time configuration

## Reconfiguration

## Help needed
