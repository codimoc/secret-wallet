## Disclaimers

+ **Privacy disclaimer**: This application is entirely open-source and non-commercial. It is free to download and use for securing personal information. The user of this application is uniquely responsible for setting up his/her own storage account on Amazon AWS. This application is simply a tool to facilitate the communication between the user's machine and the remote store. Under no circumstances does this application have access to, collect, manage or transfer information owned by the the final user of the application.


+ **Liability disclaimer**: This application does its best to provide means of securing data on a remote store, as explained in the documentation below. By reading this document and/or by browsing through the open source [code](https://github.com/codimoc/secret-wallet), the user will decide if this application satisfies his/her needs. By downloading and using this application the end user accepts full responsibility of any damage incurred as a consequence of the use of this application. To the maximum extent permitted by applicable law, the owner and developers of this application shall not be liable for any indirect, incidental, special, consequential or punitive damages, or any loss of profits or revenues, whether incurred directly or indirectly, or any loss of data, goodwill, or other intangible losses, resulting from the use of this application.

## Warning
This application was written and designed for Linux and provides somewhat reduced functionalities on Windows systems. The original design was aimed at a command line tool that integrates inside a Linux shell like bash, with some functionalities running in the background. From version 0.4 onwards, a bespoke secret_wallet **shell** has been added, addressing most of the
limitations on Windows platforms. By Launching the **shell** with the command line  _secret_wallet_shell(.exe)_  the application runs inside its own environment, hence keeping a short memory of the password used in previous and recent queries, within a specified timeout period.
This facilitates a repeated usage of the application, without the need of retyping the password. Please see a more detailed explanation in the [shell](#shell) section below.


## Introduction
Like many wallet applications, this Python-based utility addresses the requirement of having a single point of access for the large amount
of sensitive information that our social-media presence requires.

If simple and memorable passwords are bad, recycling the same password over and over is evil: with one access compromised, all our secrets and sensitive information are potentially exposed.

Producing and remembering a different complex password for each remote account is hard, and it can quickly become unmanageable when passwords need changing frequently.

To store these secrets on paper is not very smart either: a notebook can be safely tucked away in a locked drawer,
but it is not very helpful when trying to remember the login credentials of a personal banking site or a private health insurance, while on holiday abroad.

And if the secret wallet travels with us, it is constantly at risk of being compromised or lost. And with it, all the secrets it contains.

Keeping these secrets on an electronic wallet instead, on a PC, a tablet or a phone, is as safe as the device where these secrets are stored on.
Data can be encrypted on a hard drive, but the disk can fail, the phone can be stolen, the tablet forgotten on a plane.

## Index
*  [motivations](#motivations)
*  [description](#description)
*  [concepts](#concepts)
*  [requirements](#requirements)
*  [installation](#installation)
*  [first time configuration](#configuration)
*  [password strength](#passwords)
*  [syntax](#syntax)
*  [commands](#commands)
*  [usage](#usage)
*  [the secret wallet session](#session)
*  [customization of parameters](#customization)
*  [reconfiguration](#reconfiguration)
*  [shell and Windows usage](#shell)
*  [work in progress](#work)
*  [help needed](#help)
*  [FAQ](#faq)
*  [Release Notes](#notes)

## <a id="motivations"></a>Motivations

Fundamentally there are two conflicting requirements to keep in mind: ease of access for the data-owner and protection from unwanted access.

Let's consider these in detail:
* **accessibility**:
    * The data should be available remotely, from any location.
    * There should be a single copy of the stored data.
    * The data should be accessible from different devices, of different type.
    * Data retrieval should be  _user-friendly_  and fast.
    * Data retrieved should be in a format that can be easily cut & pasted into a login form from the same device.
* **security**:
    * Sensitive data, stored remotely on a server or on the cloud, should be encrypted.
    * There should be no risk of  _man in the middle_ ,  _i.e._  data should be transmitted in encrypted format.
    * Data access should be protected by different and independent security tokens.
    * Encryption should happen locally, on trusted devices. Trusted devices can be configured
    by using the same hash-key for encryption (the salt). The generation of this hash-key should be password protected.
    * The memorable password used as the encryption key should be remembered by the owner and not stored.
    * The password for configuring the trusted device should be different from the memorable password used
    to encrypt the data.
    * There should be a third layer of protection on the remote store.


## <a id="description"></a> The secret wallet, by codimoc, and security considerations

This Python-based application strives to fulfil these requirements and motivations by:

*   Using the AWS DynamoDB as the remote store, and relying on the security layer of the Amazon cloud as the third layer of protection.
*   using the **cryptography** package for local encryption (on device).
*   using the AWS **boto3** package to interact with the remote store.
*   securing both devices and secrets with independent and strong passwords (**password_strength** package): these are the first two layers of protection.
*   providing console-based interaction with the secret wallet (for the time being)

Securing the allowed devices with a configuration password provides safety against misuses of the store, once the memorable password is
compromised by accident. For example, if the memorable password is confided to others or guessed, only pre-configured devices can access
the secrets.

On the other hand, if a device is lost or stolen, the memorable password is still required to access the secrets. The AWS security layer does not help in this case,
with the AWS secure credentials helpfully located on the compromised device's file system.

## <a id="concepts"></a>Concepts
The basic unit of information stored on the remote DB is a **secret**.
Each secret is identified by a pair of two keys, the domain key and the access key:
*   **domain**: it is the principal context of that secret,  _e.g_  the name of a service provider for which some access credentials are needed.
*   **access**: it is a sub-context of the  _domain_ ; for example if the main domain is a utility provider providing both a gas and electricity accounts, we might have two secrets with the same domain but different accesses. This separation of domain and access facilitates queries to the DB, since we might want to know all the accesses for a given domain, or all the available domains in the wallet.

Each secret contains three nullable items of data:
*   **uid**: the user id, or the login credential for that secret. This is stored as an encrypted value,
*   **pwd**: the password required to login in the account with the given user id, for example the user id and password for an online shopping account.
This password-data is also stored encrypted at the source (from the local client),
*   **info**: a map of extra information regarding this secret. This meta-data is open-ended, in the sense that anything can go into this dictionary, and it is stored as a json dictionary, with keys not encrypted and values encrypted. For example, if the secret refers to a shopping account, the map could be as follows:


    {'telephone' : 1234,
     'delivery-agent' : 'Fast delivery Limited'}


## <a id="requirements"></a>Dependencies and requirements
The **secret wallet** uses the AWS cloud to store the secret information; in particular it relies on the *no-SQL* service, known as AWS *DynamoDB*. This is a database with tables that can be defined by the declaration of one or two primary keys. The remaining part of the schema can change and grow based on the data inserted, depending on the format of the records we want to store. The advantage of this storage solution are:
*   It is a remote storage widely available on the Amazon cloud.
*   It is easy to use and create new tables,
*   It is available in the [AWS Free Tier](https://aws.amazon.com/free/?all-free-tier.sort-by=item.additionalFields.SortRank&all-free-tier.sort-order=asc) package that Amazon offers as an entry point into their echo-system.

In order to use the **secret wallet** it is necessary to use an Amazon AWS account,  or create a new one. This can be done quickly and easily from the [AWS Free Tier](https://aws.amazon.com/free/?all-free-tier.sort-by=item.additionalFields.SortRank&all-free-tier.sort-order=asc) page. Once the account has been created, three pieces of information are required for the **secret wallet**:
*   the **aws_access_key_id**: to identify the account
*   the **aws_secret_access_key**: which can be created after logging into the account; this key can be regenerated several times.
*   the **region**: the physical location of the server, possibly close to the location of usage.

These three records should be noted down when creating the account or copied onto the clipboard or on a file. They will be needed later, when [configuring](#configuration) the **secret wallet**.

It should be noted that the initial AWS keys, produced on creation of the new account, are root credentials for that account. It is safer, once logged into this new AWS account, to generate a different IAM role with limited access, for example a programmatic user, and to use the relative credentials instead. Instruction on how to do this can be found [here](https://aws.amazon.com/iam/).

## <a id="installation"></a>Installation
The **secret wallet** is installed in the usual manner, as any other python packages, and requires a minimum Python version of 3.6.
The installation is done with:

    pip install secret-wallet-codimoc

After installing all the dependencies from other python packages,  it produce three new executable scripts:
*   **secret_wallet** for the command line management of the secret wallet and
*   **secret_wallet_conf** for the first time configuration as described below
*   **secret_wallet_shell** to operate the secret wallet directly in shell mode (mostly for Windows users)

## <a id="configuration"></a>First time configuration
Configuring the **secret wallet** is required in order to save both the AWS credentials for the Amazon cloud and the device's configuration key, which is the first layer of security to protect your secrets. This configuration also creates the DynamoDB table used to store the secrets.

This *first time configuration* is performed by running the **secret_wallet_conf** script from the command line. This script is interactive, in the old way of *questions and answers*, and provides some default values when possible.
It is divided into two separate steps, each of which can be skipped. Skipping a step allows to avoid overwriting credentials, if the system was partially configured, and a partial change of configuration is desired.

These steps are:
*   Storing the **AWS credentials**: this results in creating or modifying the *credentials* file in the *.aws*  directory, located in the user home directory. This file is typically divided into separate sections. This allows to persist  different connections to different services on the Amazon cloud. The section relevant to the **secret-wallet** is market with the heading [secret-wallet].
*   Storing the **secret wallet configuration**: this step persists the information in the *secretwallet.json* file in the *.secretwallet* directory, located in the user home directory. This configuration file is used to store the device encryption key, the name of the AWS connection profile and the table name where the secrets are stored. This file is also used to store customization parameters as described in [this section](#customization).

When questions are asked during the configuration, please type the first letter of the answer (e.g. *s* for *skip*) to select that choice. Whenever a default value is suggested, simply hit the *Return* button to confirm that choice.

## <a id="passwords"></a>Password strength
Strong passwords are required by this application.
Whenever a new password is needed, two verification steps are performed:
*   verify that the password is strong
*   verify that the password is correctly typed, by re-entering it a second time.

A chosen password is considered to be strong under the following requirements:
*   At least eight characters long
*   Should contain  at least one upper-case character
*   Should contain  at least one number
*   Should contain  at least one special character (!,~,^,@...)

Only two different passwords are ever required: the configuration password to produce the device's encrypted key and the memorable password.

The first password for the **device encryption key** will be used only when configuring the device, but must be remembered when configuring additional devices. Different configuration keys will result in an **InvalidToken** error when retrieving secrets saved by a different device.

The **memorable password** is used whenever saving or retrieving secrets. This password should always be the same, and can only be changed by performing a full [reconfiguration process](reconfiguration). To prevent retyping this password many times over, a session is opened and it runs in the background keeping track of the password for a short period of time. This will be discussed in [this section](#session).

## <a id="syntax"></a>Syntax
The syntax of the **secret_wallet** script is:

    secret_wallet <command> [options]


where the options are different for different commands. To get a list of available commands simply type:


    secret_wallet help

Please be aware that not all commands are be available in the first releases of this application.

To find about the available options for a given command, just type:


    secret_wallet <command> -h


For example, the options for the *set* command can be displayed by:

    secret_wallet set -h

To avoid possible errors, please remember to enclose the textual arguments within single or double quotes, when these arguments contain spaces or special characters.

## <a id="commands"></a>Commands
This section describes the main commands of this application:

*	**set**: Add or change a secret in the wallet. This could be an entire new secret, with all the information passed inline or an update of an existing secret. What is set with this command determines the content of a secret, identified by the domain, access pair. Key values pairs, as defined by the -ik and -iv options, can be added incrementally by multiple calls to the set command.
*	**get**: Retrieves the information stored inside a secret, as identified by the domain, access pair. These two fields need to be passed by using the -d and -a options.
*	**delete**: Deletes an existing secret, as identified by the domain, access pair. These two fields can be passed by using the -d and -a options. If only the domain is given, all secrets for that domain are deleted. When the -ik option is given with a key name, the corresponding entry in the info dictionary is removed, only if both domain and access are given and they identify an existing secret.
*	**rename**: Renames a secret, as identified by the domain, access pair. A new domain name can be passed with the -nd option and a new access name can be passed with the -na option. Both domain and access can be changed at the same time or on their own.
*	**list**: List a set of secrets. With no option passed, all secrets are returned. Alternatively it is possible to filter secrets by passing a domain name: all secrets for that domain will be returned.
*	**query**: Searches for secrets containig a given subtext in either their domain or access names, or both. By using the explicit -d and -a options, it is possible to limit the search to domain names or access names only. Alternatively it is possible to pass a subtext without any specification in front (i.e. without -d or -a) and the search of that pattern will include both domain and access names.
*	**qget**: Searches for secrets containig a given subtext in their domain or access names. Once a list of secrets
that match the given pattern is found, the secrets are tagged with a progressive number and the user can select the one to retrieve and display.
*	**conf**: Configures some parameters for this application. It is possible to list all parameters with the -l option, or to configure the timeout and lifetime (in seconds). The timeout is the amount of time in seconds along which the memorable password is remembered without been re-asked. The lifetime determines the lifetime of the background   process that manages the temporary storage of the memorable password. The value of the lifetime parameter should be bigger than the value of the password timeout.
*	**reconf**: Reconfigures either the memorable or the device password. All secrets will be re-encryted with the changed password. It is not possible to change both passwords at the same time. Depending on the size of the wallet, this operation might take some time. A backup of the old table is also performed.
*	**help**: Display the main help.
*	**version**: Returns the release version number.
*	**shell**: Works in a separate shell. This is to facilitate usage on a Windows platform, in the absence of backround processes.
*	**session**: Starts a background session for keeping track of the memorable password for a short while. This is only for testing since this process is started automatically when needed by the secret_wallet. The lifetime parameter sets the lifetime of the session in seconds, the timeout the time in second for which the memorable password is kept, and the value is what has to be remembered.
*	**client**: Client command to invoke the background session. This is for testing only. The action allows to get the session value, set the value, stop the background session and test if it is running.
*   **dump**: This command is used to dump a full text representation of the entire secret wallet. This full dump goes directly to the screen terminal or to a chosen file path, if the  _-f_  option is used. Clearly it is up to the user to secure or delete this file, since it contains all the un-encrypted secrets.
*   **save**: This command is used to save a full representation of the entire secret wallet into  _json_  format. This can be used as a backup for later restoration of the wallet if required. Again this information can be sent directly to the screen terminal or to a file with the  _-f_  option. Clearly it is up to the user to secure (save in encrypted format for future use) or delete this file, since it contains all the un-encrypted secrets.
*   **load**: This command is used to restore the entire secret wallet from a backup file, stored in  _json_  format. It requires the  _-f_  option to specify the location of this  _json_  file. The command will not overwrite secrets which are already present in the secret store, and only what is missing is reloaded. In this way a full reload will not change the timestamps of existing secrets.


## <a id="usage"></a>Usage
As mentioned above, in the early releases of this application the interaction with the secret wallet is limited to the command line interface. A typical user would add secrets, retrieve secrets and look at a list of secrets stored in the remote wallet.

Let's consider a realistic example: the energy provider *Smart Energy Ltd* provides both gas and electricity to our customer. It provides a single access through their web portal, to manage both the gas and electricity accounts. It requires a normal access with a login and password, and gives some customer's support through a telephone hot-line. In summary:

| Field | Value |
| ---- | ---- |
| user id | joe@email.com |
| password | xy67Gh!8 |
| gas account | G15003798 |
| electricity account | E15003799 |
| hotline | 0800 123456 |

Fundamentally, one login and password to store and some extra information. We could to use *energy* as the domain name  and *smart energy* as the access name.

We start by inserting the user id and password:

    secret_wallet set -d energy -a 'smart energy' -u 'joe@email.com' -p 'xy67Gh!8'

Notice that we have wrapped some of the fields in single quotes. This to ensure that the shell interpreter (bash in my case) does not misinterpret some special characters in the password field or the space in the access field.

A memorable password is first asked and then verified, and the data is entered in the wallet. We can check that the secret is there by typing:

    secret_wallet list

We then add the extra information, bit by bit. In fact an update of the secret is performed instead of a new insertion, whenever the same domain and access values are used:

    secret_wallet set -d energy -a 'smart energy' -ik 'gas account' -iv G15003798
    secret_wallet set -d energy -a 'smart energy' -ik 'electricity account' -iv E15003799
    secret_wallet set -d energy -a 'smart energy' -ik 'hotline' -iv '0800 123456'

All done! We can now look at the full secret stored:

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

It is important to verify the integrity of the secret with the *get* command straight after insertion. This is to guarantee that all the secret data was stored with the same password. If any data had a different password when stored, the retrieval would produce an **InvalidToken** error.

If this happens, we should delete the record and start again. To delete the record simply use the *delete* command:

    secret_wallet delete -d energy -a 'smart energy'

At this stage it is interesting to compare with what stored remotely. After logging in with the AWS Management Console, and selecting the DynamoDB service, all items in the target table should appear encrypted.

## <a id="session"></a>The secret-wallet session
When many secrets  need to be inserted sequentially, it is very tiring to type the memorable password twice for each insertion with the *set* command. For this reason two background processes are started when the first password is entered.

The first process keeps the memorable password alive for a short period of time, so that reiterated insertions or retrievals within this period don't require the re-insertion of the same password. The default **timeout** is of 60 seconds but can be customized manually as described in the [next section](#customization). After the timeout period lapses, this process is kept alive but the password is forgotten until the next password request.

The second process has a **lifetime** of 10 minutes, which is also manually customizable with a different value. This process' task is to kill the first process when the lifetime has expired. At the end, both processes are terminated, only to be restarted at the next password request.


## <a id="customization"></a>Customization of parameters
The application's custom parameters, like the device key, the aws profile name and the table name, are serialized in the json file located with path *home/.secretwallet/secretwallet.json*, where *home* is the path to the home directory.
Most of these parameters are set only once when configuring the system for [the first time](#configuration).
However this file can also be used to store custom parameters that modify the behavior of the application. In particular the timeout and the lifetime of the [session for the memorable password](#session) can be changed and persisted in this file. This can be done using the **conf** command with the option *-to* (timeout) and *-lf* (lifetime) as below:

        secret_wallet conf -to 30 -lf 120

where the values are in seconds, *i.e.* timeout of 30 seconds and a lifetime of 2 minutes.

It is also possible to change the verbosity of information logged int the  _secretwallet.log_  file located in the  _.secretwallet_  home directory, by passing a logging level with the  _-ll_  option.

## <a id="reconfiguration"></a>Reconfiguration
The reconfiguration process allows the re-encryption of all existing secrets when the device password or the memorable password are changed. In this scenario all secrets need to be retrieved, decrypted and re-encrypted with the new key(s). This can be done with the **reconf** command, with optional parameters set to *-d* for a change of device password, and to *-m* for a change of memorable password.

When this action is performed, a backup copy of the table containing the secrets is stored on the cloud. This can be used to restore the state of the table later on, if a roll-back is required.

## <a id="shell"></a>The Shell and Windows usage
It is possible to run the  _secret_wallet_  inside its own shell by either calling the shell sub-command or by invoking directly the shell start-up script as below:

        secret_wallet shell
or

        secret_wallet_shell

A new prompt will appear (:>) and the shell can be terminated at any time by typing the  _quit_  command. There are three advantages of operating inside the shell:

*   No need to type the program name at the beginning of the command line. The original commands from the bash shell:

        secret_wallet help
        secret_wallet list
        secret_wallet query -d xxx
        secret_wallet get -d xxx -a yyy

Inside the shell are now:

        help
        list
        query -d xxx
        get -d xxx -a yyy
        quit

*   A history of the previous command can be replayed with the up arrow, and some command auto-completion are in the future pipeline

*   A timed-out memory of the recently used memorable password facilitates repeated queries, without the need of retyping the memorable password. This is particularly aimed at *Windows* users, who don't rely on the bash shell and Linux background daemons and who did not have access to this feature in previous versions. The configuration of this password time-out (the default is 60 seconds) can be done inside the shell. For a two minutes' time-out, for example, the command would be:

        conf -to 120



## <a id="work"></a>Work in progress
Coming soon, in the next releases, there will be some feature improvements and fixes, like:

*   adding new commands to the command line interface, like query capabilities,
*   adding batch processing of secrets' insertion
*   required bug fixes.

On a longer time scale:
*   Adding a graphical user interface

## <a id="help"></a>Help needed
This simple application has the potential of becoming a useful productivity tool, and will require lot's of work for new features and better user interaction.
Help is needed and welcome. Please visit the the [github page](https://github.com/codimoc/secret-wallet) and raise new issues, or contact the author via email from the email address you will find in the secret-wallet page on [pypi](https://pypi.org/).

## <a id="faq"></a>FAQ
A *frequently asked questions* is maintained [here](https://github.com/codimoc/secret-wallet/wiki/FAQ).

## <a id="notes"></a>Release Notes
The *Release Notes* are maintained [here](https://github.com/codimoc/secret-wallet/wiki/Release-Notes).
