[![Gitter](https://badges.gitter.im/dnsshe/community.svg)](https://gitter.im/dnsshe/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=body_badge)
[![NuGet](https://img.shields.io/nuget/v/NN.Dnsshe.svg?style=flat)](https://www.nuget.org/packages/NN.Dnsshe/)

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

The native binaries are not provided in this repository.  
Check download instructions on the relevant project page.

## Windows

`vcpkg install libssh`  
`vcpkg install libssh2`

## Ubuntu

`sudo apt install libssh-dev`  
`sudo apt install libssh2-1`

## macOS

`brew install libssh`  
`brew install libssh2`  


# Project organization

Every library has its own namespace, e.g. *libssh* - *NN.Dnsshe.Libssh*.

The top level namespace contains higher level functions.

**Native** namespace contains native methods and data structures.  
The function declarations are preserved with SafeHandle change.  
