#The secret wallet, by codimoc

Like many wallet applications, this Python-based utility addresses the requirement of having a single point of access for the large amount
of sensitive information that our social-media presence produces.

If simple and memorable passwords are bad, recycling the same password over and over is evil: with one access compromised, all our secrets and sensitive information are potentially exposed.

Producing and remembering a different complex password for each remote account is hard, and it can quickly become totally unmanageable when passwords need changing frequently.

To store these secrets on paper is not very smart either: a notebook can be safely tucked away in a locked drawer, 
but this is not very helpful when trying to remember the login credentials of a personal banking or private health insurance site, while on holiday abroad.

And if the secret wallet travels with us, it is constantly at risk of being compromised or lost. And with it, all the secrets it contains.

Keeping these secrets on an electronic wallet instead, on a PC, a tablet or a phone, it is as safe as the device these secrets are on. They can be encrypted on a hard drive, but the disk can fail, the phone can be stolen, the tablet forgotten on a plane... And so on.

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
    * There should be no risk of _men in the middle_, _i.e._ data should be transmitted in encrypted format,
    * Data access should be protected by different and independent security tokens,
    * Ideally encryption should happen locally, on trusted devices. Trusted devices should be configured
    by storing a hash-key. The generation of this hash-key should be password protected, 
    * The memorable password used as encryption key should be remembered by the owner and not stored,
    * The password used to configure the trusted device should be different from the memorable password used
    to encrypt the data,
    * There should be a third layer of protection on the remote store. 






## Security considerations

## Concepts

## Syntax

## First time configuration

## Usage


 
Fill this document with a full description usin markup format as described in
https://guides.github.com/features/mastering-markdown/