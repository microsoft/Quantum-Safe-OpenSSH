###   Azure Portal __Custom Script For Linux__ extension

#### Using quantum-safe public key
To make your initial SSH connection with a quantum-safe public key, you will need to do the following:
1. Complete this VM creation process by supplying the __Administrator account__ with a valid standard RSA key or strong password. You only need this key/password to satisfy the UI and create the VM. You will provide the quantum-safe public key at a later step.
2. [Install the quantum-safe OpenSSH client](./Client.md).  
3. Generate a quantum-safe key pair.
4. Provision the VM with your quantum-safe. See [Provisioning Public Keys to VM Server](#Provisioning-Public-Keys-to-VM-Server) below to copy your quantum-safe public key to the server.


    If you want your supply your PQ public key at VM creation time, you can use the __Custom Script For Linux__ extension.

    - Output your public key to the client console:  
      `>cat ~/.ssh/<key-file>.pub`  


    - Create a bash script on your local machine named `script.sh` and paste the key data into the script.
    ```
    #!/bin/bash

    PUBLICKEY=""

    ADMINUSER=$(ls /home)
    USERFOLDER=/home/$ADMINUSER
    SSHFOLDER=$USERFOLDER/.ssh
    AUTHORIZEDKEYS=$SSHFOLDER/authorized_keys

    # create .ssh/authorized_keys if not found
    if [ ! -e "${SSHFOLDER}" ] ; then
      mkdir $SSHFOLDER
      chmod 700 $SSHFOLDER
      chown ${ADMINUSER}:${ADMINUSER} $SSHFOLDER
      touch $AUTHORIZEDKEYS
      chmod 600 $AUTHORIZEDKEYS
      chown ${ADMINUSER}:${ADMINUSER} $AUTHORIZEDKEYS
    fi

    echo $PUBLICKEY > $AUTHORIZEDKEYS

    exit 0
    ```


Replace `<key-data>` with the public key data output on the client. Replace the `<your-user-name>` with your Administrator user name from the VM creation screen.

  - In the Azure Portal at the VM creation screen. Enter in your desired settings on the __Create a virtual machine__ page.  
  Add the Administrator user name and use a valid standard public key or a password. We'll use our PQ public key to log in later.

      >__Note:__  
      >By default, the SSH server on the VM has password authentication disabled.  If you give the Administrator account a password here, it will enable password authentication on the server.
  
  
  - After the VM data is filled in,click the __Advanced__ link near the top of the page.  
  At the __Advanced__ page click the __Select an extension to install__ item and a list of extensions will appear on the right side of the screen.  
  Select the __Custom Script For Linux__ extension and a panel for that extension will expand.  Click the __Create__ button at the bottom of that panel.  
  Now use the file browser to find the file script named `script.sh` you created earlier.  
  Once selected, click the __OK__ button and extension will now be listed in the extensions list for the VM.  
  Now complete the VM creation process. When the VM is ready, you should be able to log in from your PQ client with the PQ public key.
