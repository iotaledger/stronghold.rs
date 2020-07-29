# Stronghold Engineering Specification
[engineering-spec]: #engineering-spec

## Frontmatter
[frontmatter]: #frontmatter
```yaml
title: Stronghold
stub: stronghold
document: Engineering Specification
version: 0000
maintainer: Daniel Thompson-Yvetot <daniel.yvetot@iota.org>
contributors: [Dave de Fijter <dave.defijter@iota.org>, tensorprogramming <tensordeveloper@gmail.com>, Daniel Thompson-Yvetot <daniel.yvetot@iota.org>, Marcelo Bianchi <marcelo.bianchi@iota.org>]
sponsors: [Navin Ramachandran <navin@iota.org>]
licenses: ["MIT/Apache-2", "CC-BY-INTL-3.0"]
updated: 2020-July-24
```

## Summary
[summary]: #summary
This document introduces the High-Level Specification of the Stronghold, specifically the External Signer Specifications.

## Logical System Design
[system-design]: #system-design

A Stronghold is composed of two underlying libraries:
- iota.rs (the client libraries)
- engine (low-level stronghold)

Furthermore, it provides an actor wrapper (for IOTA's `actors.rs`) that enables it to participate in message-passing architectures, such as the IOTA Wallet.

The purpose of the Stronghold is to make a unified interface to these libraries and provide a secure actor interface for projects that choose to implement the Actor Model.

## Programming Language
[language]: #language
The Stronghold is written and maintained in Stable Rust.

## Environment
[environment]: #environment
A Stronghold should be able to run on any hardware where the rust compiler is available. Furthermore, on platforms where this is challenging (like some embedded platforms), it SHOULD be made available with C bindings.

## Schema
[schema]: #schema
The schemas are currently under review. They can be inspected in `/spec/2-RFP/PROPOSALS/SCHEMAS`

## Functional API
External signer specifications

### Introduction

This document specifies a possible implementation of an external signer interface from the client libraries. This allows you to let external devices or protocols do actions for you like generating addresses or signing transactions without needing explicit access to the seed. The external signer is part of the Higher Level Client Library spec and makes it possible to allow extension of external signers later on without having to change the client library API.


### URI Schemes

In order to allow interaction with many devices and protocols for external signing functionality now and in the future without having to change the higher level client library syntax we can use URI’s to define how to connect to the external signers. The URI Scheme is protocol independent and purely serves as a hint to the lower level implementation as to where and how to connect to this service/device.

Examples:

**stronghold://**

The default external signer to use when no explicit seed is provided. No additional information is provided so this connects to the stronghold instance on the local machine through whatever stronghold prefers.

**stronghold://10.0.0.103:4832**

Stronghold on an external server, in the case defined by an IP address and Port. Note that we don’t say http/https/tcp/udp, this is up to the stronghold implementation to define.

**stronghold://10.0.0.103:4832&cosign=10.0.0.104:4844&cosign=10.0.0.105:4837**

Extremer example of using optional arguments in the query string for potential extra functionality, like in this case using 2 additional stronghold servers on different IPs to co-sign.

**ledger://**

Ledger device on local USB drive, without arguments it just looks for the first it can find

**ledger://ttyUSB0 or ledger://COM4**

Ledger device explicitly running on a specific port, this can vary based on OS identification of devices.

**https://dave:somepassword@sign.iota.works**

A https based API for signing given a username and password, as an example, no need to have this implemented right away.


### Additional methods for the client libraries using this

If there’s an external signer given or detected instead of a seed that is provided it will load the following methods that should be used in the client libs instead of standard functionality whenever the seed normally is used. These commands should probably reside in their own namespace/crate for external signing functionality.


#### SendCommand(command, data)

**implementation per signer type, not generic**

A private async function to call a command on an external signing interface; Basically the wrapper that converts generic commands called from within the client libraries to specific external signer commands. This should be implemented per external signer. This is basically to abstract the conversion between the generic external signer commands as listed below and the foreign interface (converting to a JSON/HTTP request for example).


##### Parameters


<table>
  <tr>
   <td>Field
   </td>
   <td>Type
   </td>
   <td>Description
   </td>
  </tr>
  <tr>
   <td><strong>command</strong>
   </td>
   <td>String
   </td>
   <td>The name of a command to call on the remote signing server, this can be anything as long as the remote server accepts the name of that command.
   </td>
  </tr>
  <tr>
   <td><strong>data</strong>
   </td>
   <td>Struct
   </td>
   <td>The data to be sent along with the command; the structure of this data differs from command to command.
   </td>
  </tr>
</table>



##### Return

Ok: The result of the command executed, to be processed by the calling function; Err: A human readable error message


#### CreateAccount(identifier)

Utilizes SendCommand to call a command to generate a new seed which will be stored on the external signer and can be referenced from there on by the given identifier. This can be a name or a number; If you provide a name however and the device/service only accepts numbers/indexes (Ledger devices for example) it should throw an error message instead.


##### Parameters


<table>
  <tr>
   <td>Field
   </td>
   <td>Type
   </td>
   <td>Description
   </td>
  </tr>
  <tr>
   <td><strong>identifier</strong>
   </td>
   <td>String
   </td>
   <td>Account name or index; Name is preferred but if the external signer only accepts index numbers a Index should be provided instead (or a error will be thrown)
   </td>
  </tr>
</table>



##### Return

Either a success response or an Error with human readable explanation about why this failed (Ok, Err)


#### GenerateAddress(account, index=None)

Utilizes SendCommand to generate an address, if the index is provided it will generate the address for the provided index, if not it will use the next available index (only if the external signing service has its own state for storing used indexes per seed).


##### Parameters


<table>
  <tr>
   <td>Field
   </td>
   <td>Type
   </td>
   <td>Description
   </td>
  </tr>
  <tr>
   <td><strong>account</strong>
   </td>
   <td>String
   </td>
   <td>Identifier of an existing account created with CreateAccount; Errors out if this account does not exist.
   </td>
  </tr>
  <tr>
   <td><strong>data</strong>
   </td>
   <td>Struct
   </td>
   <td>The data to be sent along with the command; the structure of this data differs from command to command.
   </td>
  </tr>
</table>



##### Return

Ok: The generated address - Err: A human readable error message


#### SignMessage(account, message):

Utilizes SendCommand to sign a message given an account identifier and a message/transaction object.


<table>
  <tr>
   <td>Field
   </td>
   <td>Type
   </td>
   <td>Description
   </td>
  </tr>
  <tr>
   <td><strong>account</strong>
   </td>
   <td>String
   </td>
   <td>Identifier of an existing account created with CreateAccount; Errors out if this account does not exist.
   </td>
  </tr>
  <tr>
   <td><strong>message</strong>
   </td>
   <td>Message/Transaction
   </td>
   <td>The message to sign, receives a Transaction/Message object from the Higher Level Client Lib to sign.
   </td>
  </tr>
</table>



##### Return

Ok: The signed message object - Err: A human readable error message


#### ValidateMessage(account, message):

Utilizes SendCommand to validate if a message was signed using the given account identifier and a message/transaction object.


<table>
  <tr>
   <td>Field
   </td>
   <td>Type
   </td>
   <td>Description
   </td>
  </tr>
  <tr>
   <td><strong>account</strong>
   </td>
   <td>String
   </td>
   <td>Identifier of an existing account created with CreateAccount; Errors out if this account does not exist.
   </td>
  </tr>
  <tr>
   <td><strong>message</strong>
   </td>
   <td>Message/Transaction
   </td>
   <td>The message to validate including its signature, receives a Transaction/Message object from the Higher Level Client Lib to sign.
   </td>
  </tr>
</table>



##### Return

Ok: The signed message object was validated as signed with this account - Err: A human readable error message


#### Encrypt(account, data):

Utilizes SendCommand to encrypt data with the provided account identifier


<table>
  <tr>
   <td>Field
   </td>
   <td>Type
   </td>
   <td>Description
   </td>
  </tr>
  <tr>
   <td><strong>account</strong>
   </td>
   <td>String
   </td>
   <td>Identifier of an existing account created with CreateAccount; Errors out if this account does not exist.
   </td>
  </tr>
  <tr>
   <td><strong>data</strong>
   </td>
   <td>String
   </td>
   <td>The actual string to encrypt
   </td>
  </tr>
</table>



##### Return

Ok: The encrypted string - Err: A human readable error message


#### Decrypt(account, data):

Utilizes SendCommand to decrypt data with the provided account identifier


<table>
  <tr>
   <td>Field
   </td>
   <td>Type
   </td>
   <td>Description
   </td>
  </tr>
  <tr>
   <td><strong>account</strong>
   </td>
   <td>String
   </td>
   <td>Identifier of an existing account created with CreateAccount; Errors out if this account does not exist.
   </td>
  </tr>
  <tr>
   <td><strong>data</strong>
   </td>
   <td>String
   </td>
   <td>The encrypted data string
   </td>
  </tr>
</table>



##### Return

Ok: The decrypted string - Err: A human readable error message


#### StoreSecret(account, secret_name, secret_value):

Utilizes SendCommand to store a secret on the external signer, this can only be implemented if the external signer supports this and should throw a NotImplemented error if it doesn’t (for example with the Ledger devices).


<table>
  <tr>
   <td>Field
   </td>
   <td>Type
   </td>
   <td>Description
   </td>
  </tr>
  <tr>
   <td><strong>account</strong>
   </td>
   <td>String
   </td>
   <td>Identifier of an existing account created with CreateAccount; Errors out if this account does not exist.
   </td>
  </tr>
  <tr>
   <td><strong>secret_name</strong>
   </td>
   <td>String
   </td>
   <td>The unique key name of the secret, will overwrite existing secrets with the same name if the same name is used (upsert)
   </td>
  </tr>
  <tr>
   <td><strong>secret_value</strong>
   </td>
   <td>String
   </td>
   <td>The value of the secret to store
   </td>
  </tr>
</table>



##### Return

Ok: Success response - Err: A human readable error message


#### RetrieveSecret(account, secret_name):

Utilizes SendCommand to fetch a secret from the external signer, this can only be implemented if the external signer supports this and should throw a NotImplemented error if it doesn’t (for example with the Ledger devices).


<table>
  <tr>
   <td>Field
   </td>
   <td>Type
   </td>
   <td>Description
   </td>
  </tr>
  <tr>
   <td><strong>account</strong>
   </td>
   <td>String
   </td>
   <td>Identifier of an existing account created with CreateAccount; Errors out if this account does not exist.
   </td>
  </tr>
  <tr>
   <td><strong>secret_name</strong>
   </td>
   <td>String
   </td>
   <td>The unique key name of the secret to fetch for this account, Errors out if the secret does not exist.
   </td>
  </tr>
</table>



##### Return

Ok: Success response with secret value - Err: A human readable error message

