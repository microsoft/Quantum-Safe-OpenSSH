# Connect Client to Server

- [Overriding Algorithms](#overriding-algorithms)  
    - [Set SSH Client Algorithms](#set-ssh-client-algorithms) 
    - [Set SSH Server Algorithms](#set-ssh-server-algorithms) 
- [Listing Available Algorithms](#listing-available-algorithms)      
- [Verify Algorithm Selection](#verify-algorithm-selection)

<br>


The most common way to connect the SSH client to the SSH server is:  
`ssh [user-name@]<hostname|ip>`

```
# if your client username is different than the server username:
ssh <server-user>@123.123.123.123

# if your client username is the same as the server username you may omit the username:
ssh 123.123.123.123
```

The quantum-safe SSH client will use quantum-safe algorithms by default.  
- The selected __key-exchange algorithm__ will be the first from a default list that both the client and server support.  

- The __client public-key authentication algorithm__ will be selected based on the key(s) the client possess in `~/.ssh` and the key types the server is configured to accept.  

- The __host public-key algorithm__ will be selected based on the key(s) the server possess and the host key types the client supports.

These default algorithm selections may be overridden with optional parameters.

<br>

## Overriding Algorithms

The client and server both support optional parameters `KexAlgorithms`, `HostKeyAlgorithms`, and `PubkeyAcceptedKeyTypes` to override algorithm defaults and select specific algorithm(s) when establishing an SSH connection. 

- `KexAlgorithms` specifies what key exchange (or key encapsulation) algorithms will be allowed.  

- `HostKeyAlgorithms` specifies what host key types the server will present and the client will accept.  
    >When using the `HostKeyAlgorithms` parameter, the server must possess a key-pair of that type for the connection to succeed using public-key authentication. 

- `PubkeyAcceptedKeyTypes` specifies what public key types the client will present and the server will accept.
    >When using `PubkeyAcceptedKeyTypes`, the client must possess a key-pair of that type and the server must have an entry for that public key in its `authorized_keys` file.  
    See [Create Quantum-Safe Key Pairs](./Client.md#create-quantum-safe-key-pairs) and [Provisioning Quantum-Safe Client Keys to Server](./Client.md#provisioning-quantum-safe-client-keys-to-server).



&nbsp;
#### Set SSH Client Algorithms

```
ssh <hostname|ip> -o KexAlgorithms=<algorithm-id1>[,<algorithm-id2>,...] -o HostKeyAlgorithms=<algorithm-id1>[,<algorithm-id2>,...] -o PubkeyAcceptedKeyTypes=<algorithm-id1>[,<algorithm-id2>,...]

# Example: the client will allow two specific KEX algorithms at connection:
ssh 123.123.123.123 -o KexAlgorithms=frodo-976-shake-sha384@openquantumsafe.org,sike-p610-sha384@openquantumsafe.org

# Example: the client will allow two specific host key types at connection:
ssh 123.123.123.123 -o HostKeyAlgorithms=ssh-rsa3072-picnic3l1,ssh-rsa3072-qteslapi

# Example: the client will allow two specific public key types at connection:
ssh 123.123.123.123 -o PubkeyAcceptedKeyTypes=ssh-rsa3072-dilithium2,ssh-p256-falcon512

# Example: the algorithm parameters may be combined:
ssh 123.123.123.123 -o HostKeyAlgorithms=ssh-p256-picnicl1fs -o PubkeyAcceptedKeyTypes=ssh-rsa3072-qteslapi
```

More conveniently, these algorithm parameters may be specified in the client config file `~/.ssh/config`.
For additional client config file information, see [SSH Config File](https://www.ssh.com/ssh/config/).

```
Host myHostName
    HostName 123.123.123.123
    User myUserName
    Port 22
    KexAlgorithms frodo-976-shake-sha384@openquantumsafe.org,sike-p610-sha384@openquantumsafe.org
    HostKeyAlgorithms ssh-rsa3072-picnicl1fs
    PubkeyAcceptedKeyTypes ssh-p384-qteslapiii,ssh-rsa3072-picnicl1ur
```

&nbsp;
### Set SSH Server Algorithms

The SSH server is usually running as a service. Parameters are set in its config file `/etc/ssh/sshd_config`.
Add or edit the `KexAlgorithms`, `HostKeyAlgorithms`, and `PubkeyAcceptedKeyTypes` parameters in the config file:


```
#/etc/ssh/sshd_config
...

KexAlgorithms frodo-976-shake-sha384@openquantumsafe.org,sike-p610-sha384@openquantumsafe.org

HostKeyAlgorithms ssh-rsa3072-picnic3l1

PubkeyAcceptedKeyTypes ssh-rsa3072-dilithium2,ssh-p256-falcon512

...
```
Restart the SSH service for the configs change to take effect: `sudo systemctl restart ssh`

<br>

## Listing Available Algorithms

For a complete list of quantum-safe algorithm names see liboqs [docs/algorithms](https://github.com/open-quantum-safe/liboqs/tree/0.4.0/docs/algorithms) folder.

To list the client supported key-exchange algorithms:  
`ssh -Q kex`  

To list the client supported public-key algorithms:  
`ssh -Q sig` 

To list the SSH algorithms the server is configured to allow:  
`nmap --script ssh2-enum-algos -sV -Pn -p <ssh-port> <host-ip>`  


<br>

## Verify Algorithm Selection

You may pass the `-v` option to the SSH client to view debug information and determine which algorithms were used when establishing the connection:  
`ssh [user-name@]<hostname|ip> -v`

Scan the debug output for the following lines:  

#### key-exchange algorithm:
`debug1: kex: algorithm: ecdh-nistp384-frodo-640-aes-sha384@openquantumsafe.org`  
Algorithm `ecdh-nistp384-frodo-640-aes-sha384` was used for the key-exchange.

#### host key algorithm:
`debug1: kex: host key algorithm: ssh-rsa3072-sphincsshake256128frobust`  
Host key `ssh-rsa3072-sphincsshake256128frobust` was used by the server.

#### client key algorithm:
`debug1: Server accepts key: /home/<user-name>/.ssh/id_rsa3072_picnic3l1 RSA3072_PICNIC3L1 SHA256:<hash-of-key>`  
Client key `rsa3072_picnic3l1` was used by the client.

<br>

#
[Quantum-Safe OpenSSH for Linux VM on Azure (README)](../README.md#Quantum-Safe-OpenSSH-for-Linux-VM-on-Azure)   
[Create New Azure Virtual Machine](./CreateVM.md)  
[SSH Client Setup](./Client.md)   
[Connect Client To Server \[Top\]](#)  
[Source Code & Development](./Dev.md#source-code-/-development)
