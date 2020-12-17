# Install Quantum-Safe OpenSSH Client

- [Install Client](#install-client)
    - [Install Client From packages.microsoft.com Repo](#install-client-from-spanpackagesmicrosoftcomspan-repo)  
    - [Install Client Package From VM](#install-client-package-from-vm)  
- [Create Quantum-Safe Key Pairs](#create-quantum-safe-key-pairs)  
- [Provisioning Quantum-Safe Client Keys to Server](#provisioning-quantum-safe-client-keys-to-server)

<br>

## Install Client 
In order to connect to your VM over SSH using the quantum-safe algorithms, you will require a quantum-safe enabled SSH client.
You may install the quantum-safe SSH client from the packages.microsoft.com repo or by directly downloading the deb package from your Azure Marketplace VM.

>__Note:__  
    At this time, there are quantum-safe OpenSSH clients for:  __Ubuntu-16__, __Ubuntu-18__, __Debian-10__ 

<br>

__Record your SSH client version__

You may want to record the current version of your installed openssh-client before installing the quantum-safe client so that you may restore your client to its original version at a later time.

```
# get the package version of the installed openssh-client (for example: 1:7.2p2-4ubuntu2.8)
apt list --installed | grep openssh-client

# example result:
# openssh-client/xenial-updates,xenial-security,now 1:7.2p2-4ubuntu2.8 amd64 [installed] 
# the version would be  1:7.2p2-4ubuntu2.8
```
```
# to restore your client to a specific version
sudo apt-get install openssh-client=<version>

# example: sudo apt-get install openssh-client=1:7.2p2-4ubuntu2.8
```

<br>

## Install Client From <span>packages.microsoft.com</span> Repo

Choose the appropriate client install below for your Linux distro.

__Debian 10 Client (Buster)__
```
# install packages.microsoft.com repo key
sudo curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

# add repo to repo list (delete this file to remove repo later.)
echo 'deb https://packages.microsoft.com/repos/msr-seccrypt-debian buster main' | sudo tee /etc/apt/sources.list.d/msr-seccrypt.list

# update the package list
sudo apt-get update

# The default debian openssh-client may have a higher (newer) version number, 
# so we explicitly include the version number to force the quantum-safe client install:
sudo apt-get install openssh-client=1:7.9p1-10+deb10u2~pqc1

# Note: the version of the quantum-safe OpenSSH on packages.microsoft.com may be updated.
# Run 'apt-cache madison openssh-client' to see the currently available versions of openssh-client.
```

__Ubuntu 18.04 LTS Client (Bionic)__
```
# install packages.microsoft.com repo key
sudo curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

# add repo to repo list (delete this file to remove repo later.)
echo 'deb https://packages.microsoft.com/repos/msr-seccrypt-bionic bionic main' | sudo tee /etc/apt/sources.list.d/msr-seccrypt.list

# update the package list
sudo apt-get update

# install the client. on Ubuntu the quantum-safe client will be seen as the newest version.
sudo apt-get install openssh-client
```

__Ubuntu 16.04 LTS Client (Xenial)__
```
# install packages.microsoft.com repo key
sudo curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

# add repo to repo list (delete this file to remove repo later.)
echo 'deb https://packages.microsoft.com/repos/msr-seccrypt xenial main' | sudo tee /etc/apt/sources.list.d/msr-seccrypt.list

# update the package list
sudo apt-get update

# install the client. on Ubuntu the quantum-safe client will be seen as the newest version.
sudo apt-get install openssh-client
```

<br>

## Install Client Package From VM

This method is an alternative to installing from the packages.microsoft.com repo detailed above. 

This will download the client deb package from the VM you created over an SSH connection. The client is then installed from the downloaded package file.  

>__Note:__  This method establishes an SSH connection with your existing SSH client, using standard algorithms.

Choose the client that matches your client Linux distro, not the VM distro.

__Debian 10 Client (Buster)__
```
# download client deb package from VM (user-name is only required if your client username differs from you VM username)
scp [<user-name>@]<vm-ip-address>:clients/debian10/* openssh-client.deb

# install the deb package
sudo apt-get install --reinstall ./openssh-client.deb
```

__Ubuntu 18.04 LTS Client (Bionic)__
```
# download client deb package from VM (user-name is only required if your client username differs from you VM username)
scp [<user-name>@]<vm-ip-address>:clients/ubuntu1804lts/* openssh-client.deb

# install the deb package
sudo apt-get install --reinstall ./openssh-client.deb
```

__Ubuntu 16.04 LTS Client (Xenial)__
```
# download client deb package from VM (user-name is only required if your client username differs from you VM username)
scp [<user-name>@]<vm-ip-address>:clients/ubuntu1604lts/* openssh-client.deb

# install the deb package
sudo apt-get install --reinstall ./openssh-client.deb
```

<br>

## Create Quantum-Safe Key Pairs

To create a new quantum-safe key pair using the quantum-safe client:  
`ssh-keygen -t <key-algorithm> [-f <key-file-path>]`

Full listing of [quantum-safe signature algorithms](Algorithms.md#signature-algorithms).

Example: create a new hybrid rsa3072-picnic3l1 key-pair:  
`ssh-keygen -t ssh-rsa3072-picnic3l1` 

To see a list of available key algorithms that the client supports:  
`ssh -Q sig`


<br>

## __Provisioning Quantum-Safe Client Keys to Server__
In order to connect your SSH client to the server using public-key-authentication, you need to copy your public key to the server. Unfortunately you cannot supply a quantum-safe public key when you create the Administrator user with the Azure Portal UI. The Azure Portal UI only allows SHA-2 RSA keys.


- #### ssh-copy-id
    If you can already access the server from your client console using a password or an existing public key, you can use the `ssh-copy-id` command. This will copy a local public key to the server's `authenticated_keys` file. See [Create Quantum-Safe Key Pairs](#create-quantum-safe-key-pairs) if you have not yet created a quantum-safe key pair.  
    ```
    ssh-copy-id -i ~/.ssh/<key-file>[.pub] <server-hostname|ip>
    ```
    ```
    # Example:
    ssh-copy-id -i ~/.ssh/id_rsa3072_picnic3l1 123.123.123.123
    ```
    The key-file `.pub` extension is optional.

- #### Azure Portal __Run command__
    If your VM is already running, you can add your public key using the __Run command__ option in the Azure Portal.  
    - Open the Azure Portal. Go to the Virtual Machines page.  
        Select your virtual machine to open its __Overview__ page.  
        In the left menu under __Operations__, find the __Run command__ operation and click on it.  
        Now, in the main panel, click on __RunShellScript__ to open the __Run Command Script__ window.
    - Output your public key to your client console:  
      `cat ~/.ssh/<key-file>.pub`  
      Copy the outputted key data to the clipboard.

    - In the __Run Command Script__ window, using the command template below, paste your copied key data into `<key-data>` and replace `<your-user-name>` with your server username:  
      `echo <key-data> >> /home/<your-username>/authorized_keys`  

      Click the __Run__ button and wait for the response.
      > __Note:__  
      > After clicking the __Run__ button, it may take up to a minute to get a response.
        
      > __Note:__  
      > Occasionally when using this method, you may get a blank line between public key entries in the `authorized_keys` file. Keys appearing after the blank line will not be recognized.  
      > Run this command in the __Run Command Script__ window (replacing \<your-user-name\>) to remove any blank lines in the `authorized_keys` file:  
      `sed -i '/^$/d' /home/<your-user-name>/.ssh/authorized_keys`


<br>

#
[Quantum-Safe OpenSSH for Linux VM on Azure (README)](../README.md#Quantum-Safe-OpenSSH-for-Linux-VM-on-Azure)   
[Create New Azure Virtual Machine](./CreateVM.md)  
[SSH Client Setup \[Top\]](#)  
[Connect Client To Server](./Connect.md)  
[Source Code & Development](./Dev.md#source-code-/-development)
