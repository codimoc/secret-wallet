## Introduction
Like many wallet applications, this Python-based utility addresses the requirement of having a single point of access for the large amount
of sensitive information that our social-media presence requires.

If simple and memorable passwords are bad, recycling the same password over and over is evil: with one access compromised, all our secrets and sensitive information are potentially exposed.

Producing and remembering a different complex password for each remote account is hard, and it can quickly become totally unmanageable when passwords need changing frequently.

To store these secrets on paper is not very smart either: a notebook can be safely tucked away in a locked drawer, 
but this is not very helpful when trying to remember the login credentials of a personal banking or private health insurance site, while on holiday abroad.

And if the secret wallet travels with us, it is constantly at risk of being compromised or lost. And with it, all the secrets it contains.

Keeping these secrets on an electronic wallet instead, on a PC, a tablet or a phone, is as safe as the device these secrets are stored on.
Data can be encrypted on a hard drive, but the disk can fail, the phone can be stolen, the tablet forgotten on a plane...

## Index
*  [motivations](#motivations)
*  [description](#description)
*  [concepts](#concepts)
*  [requirements](#requirements)
*  [installation](#installation)
*  [first time configuration](#configuration)
*  [password strength](#passwords)
*  [syntax](#syntax)
*  [usage](#usage)
*  [the secret wallet session](#session)

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
* securing both devices and secrets with independent and strong passwords (**password_strength** package): these are the first two layers of protection,
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


    {'telephone' : 1234,
     'delivery-agent' : 'Fast delivery Limited'}

 
## <a id="requirements"></a>Dependencies and requirements
The **secret wallet** uses the AWS cloud to store the secret information, in particular it relies on the *no-SQL* service AWS *DynamoDB*. This is a database with tables that can be defined simply by the declaration of one or two primary keys. The remaining part of the schema can change and grow and it is data driven, *i.e.* it depends on the format of the records we want to store. The advantage of this storage solution are:
*   It is a remote storage widely available on the Amazon cloud.
*   It is simple to use and create new tables,
*   And mainly, it is available in the [AWS Free Tier](https://aws.amazon.com/free/?all-free-tier.sort-by=item.additionalFields.SortRank&all-free-tier.sort-order=asc) package that Amazon offers as an entry point into their echo-system.

In order to use the **secret wallet** it is therefore required to use or create a new Amazon AWS account. This can be done quickly and easily from the [AWS Free Tier](https://aws.amazon.com/free/?all-free-tier.sort-by=item.additionalFields.SortRank&all-free-tier.sort-order=asc) page. Once the account has been created, the three pieces of information required in order to use this app are:
*   **aws_access_key_id**: to identify the account
*   **aws_secret_access_key**: which can be generated after logging into the account; this key can be regenerated several times
*   **region**: the physical location of the server, possibly close to the location of usage.

These three pieces of information should be noted down when creating the account or copied into the clipboard or on a file. They will be required later, when [configuring](#configuration) the **secret wallet**.

It should be noted that the initial AWS keys, produced when creating the new account, are root credentials for that account. It is safer, once logged into this new AWS account, to create some IAM roles with limited access, for example a programmatic user, and to use these credentials instead. Instruction on how to do this can be found [here](https://aws.amazon.com/iam/).

## <a id="installation"></a>Installation
The **secret wallet** is installed in the usual manner, as any other python package, and requires a minimum python version of 3.6.
The installation is done with:

    pip install secret-wallet-codimoc 

This will first install all the dependencies from other python packages and will produce two new executable scripts:
*   **secret_wallet** for the command line management of the secret wallet and
*   **secret_wallet_conf** for the first time configuration as described below

## <a id="configuration"></a>First time configuration
Configuring the **secret wallet** is required in order to save both the AWS credentials for the Amazon cloud and the device's configuration key, which is the first layer of security to protect your secrets. This configuration creates also the DynamoDB table used to store the secrets on the remote server.

This *first time configuration* is performed by running the **secret_wallet_conf** script from the command line. This script is interactive, in the old way of *questions and answers*, and provides some defaults value when possible. 
It is divided into two separate steps, each of which can be skipped. Skipping a section allows to avoid overwriting credentials if the system was partially configured, and a partial change of configuration is desired. 

These steps are:
*   Storing the **AWS credentials**: this step results in creating or modifying the *credentials* file in the *.aws*  directory, located in the user home directory. This file is typically divided into separate sections. This allows to persist  different connections to different services on the Amazon cloud. The section relevant to the **secret-wallet** is market with the heading [secret-wallet].
*   Storing the **secret wallet configuration**: this step persists the information in the *secretwallet.json* file in the *.secretwallet* directory, located in the user home directory. This configuration file is used to store the device encryption key, the name of the AWS connection profile and the table name where the secrets are stored. This file is also used to store customisation parameters as is described in [this section](#customisation).  

When running the configuration script and a question is asked, type the first letter of the answer (e.g. *s* for *skip*) to select that choice. Whenever a default value is suggested, hitting the *Return* button will confirm that choice.  

## <a id="passwords"></a>Password strength
Strong passwords are required by this application and whenever a new password is needed, two verifications are performed:
*   that the password is strong
*   that the passoword is verified by re-entering it a second time.

A chosen password is considered to be strong under the following requirements:
*   At least eight characters long
*   Should contain  at least one upper-case character
*   Should contain  at least one number
*   Should contain  at least one special character (!,~,^,@...)

Only two different passwords are ever required: the configuration password to produce the device's encrypted key and the memorable password.

The first password for the **device encryption key** will be used only when configuring the device, but must be remembered when configuring another device to access the remote secret wallet. Different configuration keys will result in an **InalidToken** error when retrieving secrets saved by a different device.
  
The **memorable password** is used whenever saving or retrieving secrets. This password should always be the same and can only be changed by performing a full [reconfiguration process](reconfiguration). To prevent retyping this password many times over, a session is opened and run in the background to remember this pasword for a short period of time. This will be discussed in [this section](#session). 

## <a id="syntax"></a>Syntax
The syntax of the **secret_wallet** script is:

    secret_wallet <command> [options]


where the options are different for different commands. To get a list of available commands simply type:


    secret_wallet help

Please be aware that not all commands might be available in the first releases of this application.

To find about the available options for a given command, just type:


    secret_wallet <command> -h 


For example, the options for the *set* command can be displayed by:

    secret_wallet set -h
    
Please remember to enclose textual arguments with single or double quotes, when these arguments contain spaces or special characters, otherwise you might get some unexpected errors. 


## <a id="usage"></a>Usage
As mentioned above, in the early releases the interaction with the secret wallet is limited to the command line interface. A typical user would add secrets, retrieve secrets and look at a list of secrets in the remote wallet. 

Let's consider a realistic example: the energy provider *Smart Energy Ltd* provides both gas and electricty to our customer. It provides a single access through their web portal, to manage both the gas and electricity accounts. It requires a normal access via login and password, and gives customer's support through a telephone hot-line. In summary:

| Field | Value |
| ---- | ---- |
| user id | joe@email.com |
| password | xy67Gh!8 |
| gas account | G15003798 |
| electricity account | E15003799 |
| hotline | 0800 123456 |

Fundamentally, there is one login and one password to store and some extra info. We decide to use *energy* as the domain name  and *smart energy* as the access name.

We start by inserting the user id and password:
    
    secret_wallet set -d energy -a 'smart energy' -u 'joe@email.com' -p 'xy67Gh!8'
    
Notice that we have wrapped some of the fields in single quotes. This is to ensure that the shell interpreter (bash in my case) does not misjudge some special characters in the password field or the space in the access field.

If it all goes well, a memorable password is first asked and then verified, and the data is entered in the wallet. We can check that the secret is there by typing:

    secret_wallet list
    
We then add the extra data bit by bit. In fact an update of the secret is performed instead of an insert, whenever the same domain and access values are passed:

    secret_wallet set -d energy -a 'smart energy' -ik 'gas account' -iv G15003798
    secret_wallet set -d energy -a 'smart energy' -ik 'electricity account' -iv E15003799
    secret_wallet set -d energy -a 'smart energy' -ik 'hotline' -iv '0800 123456'
    
All done! We now want to look at the full secret:

    secret_wallet get -d energy -a 'smart energy'
    
returning:

    **********************************************************
    Secret id:
    domain              : energy
    access              : smart energy
    
    Secret credentials:
    login               : joe@email.com
    password            : xy67Gh!8
    
    Secret extra info:
    electricity account : E15003799
    gas account         : G15003798
    hotline             : 0800 123456
    
    Last updated        : 2020-02-03T08:27:03.601671
    **********************************************************

It is important to check the integrity of the secret with the *get* command straight after insertion. This is to guarantee that all the secret data was stored with the same password. If any piece of information had a different password when stored, the retrieval would produce an **InvalidToken** error.

If this happens, one should delete the record and start again. To delete the record simply use the *delete* command:

    secret_wallet delete -d energy -a 'smart energy'
    
At this stage it is interesting to compared with what stored remotely. After loggin in with the AWS Management Console, and selecting the DynamoDB service, all items in the target table should be encrypted.

## <a id="session"></a>The secret-wallet session
If you need to insert many secrets  manually, it is very tiring to type the memorable password twice for each insertion with the *set* command. For this reason two background processes are started when the first password is entered. 

The first process keeps the memorable password alive for a short period of time, so that reiterated insertions or retrievals within this period don't require the re-insertion of the same password. The default **timeout** is of 60 seconds but can be customised manually as described in the [next section](#customisation). After the timeout period lapses, this process is kept alive but the password is forgotten until the next password request.

The second process has a **lifetime** of 10 minutes, which is also manually customisable with a different value. This process' job is to kill the first process when the lifetime has expired. At the end, both processes are terminated, to be restarted at the next password request.


## <a id="customisation"></a>Manual customisation of parameters

## <a id="reconfiguration"></a>Reconfiguration

## <a id="work"></a>Work in progress

## <a id="help"></a>Help needed

## <a id="faq"></a>FAQ