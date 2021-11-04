# **D**ot**N**et**S**ecure**SHE**ll #

Pronounced dnishche (dʲnʲiɕːe) which means [bottom](https://en.wiktionary.org/wiki/%D0%B4%D0%BD%D0%B8%D1%89%D0%B5).  
A .NET wrapper for SSH libraries.

# Project Roadmap


0. Start the project
1. Add libssh declarations
    * [libssh](https://www.libssh.org/)
2. Add NuGet ☚ **We are here**
3. Add more libraries declarations
    * [libssh2](https://www.libssh2.org/)
    * [wolfssl](https://www.wolfssl.com/)
    * [OpenSSH](https://www.openssh.com/)
4. Add high level API.
5. Add native functions documentation.
6. Add generic SSH API.
7. Wrap .NET SSH libraries.

# Why another library ?

.NET SSH libraries either not freeware or abandoned.  
This library solves this problem by wrapping working and maintained SSH implementations.

# Where are the native binaries ?

Currently the native binaries are not provided in this repository.  
You can download them from the native project page.

# Project organization

Every library has its own namespace, e.g. *libssh* - *NN.Dnsshe.Libssh*.

The top level namespace contains higher level functions.

**Native** namespace contains native methods and data structures.  
The function declarations are preserved with SafeHandle change.  
