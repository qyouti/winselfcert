# winselfcert
Java native library for creating self-signed certificates in the MS CAPI certificate store. Has more functionality than using the MSCAPI security provider.

A future version of the main Qyouti application will encrypt data file and will use OpenPGP file formats for exchanging data between team members. Most users will be using Windows and it may be desirable for users' private keys to be stored in the CAPI certificate store with the "do not allow export" flag set. The MSCAPI security provider does allow Java to create certificates and key pairs in the Windows certificate store but it does not allowed nuanced options such as the "do not allow export" flag.

This library attempts to fill that gap in functionality. It can be used to create key pairs using any of the options offered by the CAPI library and those key pairs can then be used as normal with the MSCAPI security provider. For those keys that can be exported, e.g. public keys, they can be converted to other formats and used with other security frameworks or providers.
