.. role:: sh(code)
	:language: sh

Quick start
###########

Prerequisites
=============

DNS configuration
*****************

Less DNS, add server hostname and ip in */etc/hosts* file.

.. code-block:: sh

	$ echo -e "\n192.168.4.246 iccometh1804b" >> /etc/hosts 

SSH configuration
*****************

If not ssh are available, generating it with:

.. code-block:: sh

	$ ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa

Install the ssh key in the server:

.. code-block:: sh

	$ ssh-copy-id -i ~/.ssh/id_rsa iccometh1804b

Bootstrap installation
**********************

The following bootstrap script install all apt sources list and all Packages
needed for build, test and debug.

Via svn:

.. code-block:: sh

	$ sudo apt install subversion
	$ cd /tmp
	$ svn export https://iccometh1804b/svn/sadm/devel-env/cometh-bootstrap-devel.sh
	$ ./cometh-bootstrap-devel.sh
	$ rm cometh-bootstrap-devel.sh

Git configuration
*****************

.. code-block:: sh

	$ git config --global user.name "$USER"
	$ git config --global user.email "$USER@ic.fr"
	$ git config --global user.useConfigOnly true
	$ git config --global credential.username $USER
	$ git config --global credential.helper cache

Build sources
=============

Get sources
***********

In your working directory

.. code-block:: sh

	$ svn checkout https://iccometh1804b/svn/icsw/trunk icsw
	$ cd icsw
	$ make sync-src

Select board and flavours
*************************

It possible to list all board available:

.. code-block:: sh

	$ make list-boards
	$ make list-va38x_sw-flavours

Use **make help** for more detail.

For example to select switchware virtual board (for qemu) in devel mode:

.. code-block:: sh

	$ make select-va38x_sw-devel   

Build
*****

.. code-block:: sh

	$ make all

Qemu
====

Run
***

Virtual board can run in Qemu.

.. code-block:: sh

	$ scripts/qemu.sh 

Use
***

::

	###                        Staring QEMU session.                             ###
	###                                                                          ###
	### Using 'user' qemu network backend with following port                    ###
	### forwarding rules:                                                        ###
	###                                                                          ###
	### localhost:1234  --+-> Gateway [10.0.0.254] <--+--> Guest [10.0.0.1:1234] ###
	### localhost:10020 --+          ( TCP )          +--> Guest [10.0.0.1:  20] ###
	### localhost:10021 --+          ( TCP )          +--> Guest [10.0.0.1:  21] ###
	### localhost:10022 --+          ( TCP )          +--> Guest [10.0.0.1:  22] ###
	### localhost:10023 --+          ( TCP )          +--> Guest [10.0.0.1:  23] ###
	### localhost:10080 --+          ( TCP )          +--> Guest [10.0.0.1:  80] ###
	### localhost:10443 --+          ( TCP )          +--> Guest [10.0.0.1: 443] ###
	### localhost:10161 --+          ( UDP )          +--> Guest [10.0.0.1: 161] ###
	### localhost:10162 --+          ( UDP )          +--> Guest [10.0.0.1: 162] ###
	###                                               +--> DNS   [10.0.0.253]    ###
	###                                                                          ###
	### Press <ALT>-<CTRL>-a c to switch to QEMU command mode.                   ###
	### Press <ALT>-<CTRL>-a x to exit QEMU session.                             ###

	cometh login:

Some port are forwarding from localhost to qemu session.

- 1234  -- The port used by gdb server
- 1xxxx -- Standard port like ssh, sftp, snmp, http or https

In devel flavour, user **root** has no password.

SSH
***

It's possible to connect in ssh with certificate.
To install debug certificate run:

.. code-block:: sh

	$ scripts/install_devel_ssh_key.sh

After connect with command:

.. code-block:: sh

	$ ssh root@127.0.0.1 -p 10022

Exit
****

To exit, it's possible tu use **<ALT>-<CTRL>-a x** or **poweroff** in shell command.
