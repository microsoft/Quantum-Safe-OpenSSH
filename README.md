# Quantum-Safe OpenSSH for Linux VM on Azure
<br>

- [Overview](#overview)
- [Supported Algorithms](#supported-algorithms)
- [Limitations and Security](#limitations-and-security)
#
- [Create New Azure Virtual Machine](./docs/CreateVM.md)
- [SSH Client Setup](./docs/Client.md)
- [Connect Client To Server](./docs/Connect.md)
- [Source Code & Development](./docs/Dev.md##source-code-/-development)
#
- [Microsoft Open Source Code of Conduct](./CODE_OF_CONDUCT.md)
- [Security](./SECURITY.md)

<br>

## Overview
This project makes available, through the Azure marketplace, Linux virtual machines pre-configured with post-quantum enabled OpenSSH.  

VM administrators may logon and manage their VMs over a quantum-safe SSH connection when connecting with the quantum-safe OpenSSH client. Using [Visual Studio Code](https://code.visualstudio.com/) you can remotely connect to the source-code project on this VM to explore, build, and debug the quantum-safe OpenSSH applications and packages.  


This project combines the below components into these Azure virtual-machine images:
  
<br>  

__Open Quantum Safe - liboqs__  
 liboqs is cryptography library supporting post-quantum key-encapsulation and signature algorithms.  
 https://github.com/open-quantum-safe/liboqs  

__Open Quantum Safe - OpenSSH__  
 A fork of openssh-portable 7.9 that incorporates the liboqs library to support PQ algorithms in OpenSSH.  
 https://github.com/open-quantum-safe/openssh   

__Debian-OpenSSH__  
 The Debian 7.9 release of openssh-portable. This contains distro-specific application package source, patches, and configuration to support installation onto a Debian/Ubuntu distro.  
 https://salsa.debian.org/ssh-team/openssh/-/tree/debian/1%257.9p1-10+deb10u1  

__PQ Enabled OpenSSH Source__  
 The unified source code of the above projects: OQS-liboqs + OQS-OpenSSH + Debian-OpenSSH  
 You may explore, build, and debug this PQ implementation of OpenSSH.  
 https://github.com/microsoft/Quantum-Safe-OpenSSH  

__Azure VM Images__  
 Azure supported Debian and Ubuntu distro images with the liboqs enabled OpenSSH server preinstalled and configured for these specific Linux distros.  
 https://azuremarketplace.microsoft.com/Quantum-Safe-OpenSSH 

<br>

## Supported Algorithms

Details on each supported algorithm can be found in the liboqs [docs/algorithms](https://github.com/open-quantum-safe/liboqs/tree/0.4.0/docs/algorithms) folder.

These supported algorithms are a subset of the [round 2 candidates](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-2-submissions) of the [NIST standardization competition](https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization), as provided by the [Open Quantum Safe](https://openquantumsafe.org/) library. This list will change following upcoming OQS updates.

#### Key encapsulation mechanisms (KEM)

- **BIKE**
- **Classic McEliece**
- **FrodoKEM**
- **HQC**
- **Kyber**
- **NewHope**
- **NTRU**
- **SABER**
- **SIKE**
- **ThreeBears**

#### Signature schemes

- **Dilithium**
- **Falcon**
- **MQDSS**
- **Picnic**
- **qTesla**
- **Rainbow**
- **SPHINCS+**  

<br>

## Limitations and Security

__This version of OpenSSH is intended for research, prototyping, and experimentation purposes only. It is not recommended for use in production or business environments and/or to protect sensitive data.__

<br>

Per the '[Limitations and Security](https://github.com/open-quantum-safe/liboqs#limitations-and-security)' section of the Open-Quantum-Safe liboqs project:
#
_While at the time of this writing there are no vulnerabilities known in any of the quantum-safe algorithms used in this library, caution is advised when deploying quantum-safe algorithms as most of the algorithms and software have not been subject to the same degree of scrutiny as for currently deployed algorithms. Particular attention should be paid to guidance provided by the standards community, especially from the NIST Post-Quantum Cryptography Standardization project. As research advances, the supported algorithms may see rapid changes in their security, and may even prove insecure against both classical and quantum computers._

_liboqs does not intend to "pick winners": algorithm support is informed by the NIST PQC standardization project. We strongly recommend that applications and protocols rely on the outcomes of ths effort when deploying post-quantum cryptography._

_We realize some parties may want to deploy quantum-safe cryptography prior to the conclusion of the NIST PQC standardization project. We strongly recommend such attempts make use of so-called hybrid cryptography, in which quantum-safe public-key algorithms are used alongside traditional public key algorithms (like RSA or elliptic curves) so that the solution is at least no less secure than existing traditional cryptography._

_WE DO NOT CURRENTLY RECOMMEND RELYING ON THIS LIBRARY IN A PRODUCTION ENVIRONMENT OR TO PROTECT ANY SENSITIVE DATA. This library is meant to help with research and prototyping. While we make a best-effort approach to avoid security bugs, this library has not received the level of auditing and analysis that would be necessary to rely on it for high security use_
#

[\[Top\]](#quantum\-safe-openssh-for-linux-vm-on-azure)
