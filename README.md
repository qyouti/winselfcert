# winselfcert
Java library and native library for creating self-signed certificates in the MS CAPI certificate store. Has more functionality than using Sun's MSCAPI security provider.

This library attempts to fill that gap in functionality of the standard Java MSCAPI provider. It can be used to create key pairs using any of the options offered by Microsoft Windows and those key pairs can then be used as normal with the Java MSCAPI security provider. For those keys that can be exported, e.g. public keys, they can be converted to other formats and used with other security frameworks or providers.

There is a 'Demo' class which illustrates potential uses by signing/verifying and encrypting/decrypting some data using standard Java security framework. It also shows how a Windows public key can be saved in OpenPGP format with the help of BouncyCastle. (BouncyCastle is only needed for that last part - it isn't needed for creating key pairs etc.)

This GIT repository is arranged as two Netbeans projects - one for the Java classes and one for the Windows DLL. Development and building of the native Windows DLL was done using cygwin and the mingw tool chains for 64 bit windows.
