.. SPDX-License-Identifier: GPL-3.0-only
   
   This file is part of Enbox.
   Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>

.. include:: _cdefs.rst

.. _sect-api-overview:

Overview
========

What follows here provides a thorough description of how to use Enbox_'s library.
Please, head to sections :ref:`sect-main-overview` and
:ref:`sect-main-terminology` for an introduction to Enbox_ concepts.

Basically, Enbox_ library is the C framework that lies underneath Enbox_. It is
provided to carry out Enbox_ related tasks directly from C/C++ applications.

In addition to a high-level functional API, the library also comes with
additional utility functions allowing to manipulate Linux system objects in a
limited way. See section Utilities_ for more informations.

.. index:: build configuration, configuration macros

Build configuration
===================

At :ref:`Build configuration time <workflow-configure-phase>`, multiple build
options are available to customize final Enbox_ build. From client code, you
may eventually refer to the corresponding C macros listed below:

* :c:macro:`CONFIG_ENBOX_ASSERT`
* :c:macro:`CONFIG_ENBOX_VERBOSE`
* :c:macro:`CONFIG_ENBOX_DEBUG`
* :c:macro:`CONFIG_ENBOX_INCLUDE_DIR`
* :c:macro:`CONFIG_ENBOX_DISABLE_DUMP`
* :c:macro:`CONFIG_ENBOX_SHOW`
* :c:macro:`CONFIG_ENBOX_TOOL`
* :c:macro:`CONFIG_ENBOX_TOOL_LOG_SEVERITY`
* :c:macro:`CONFIG_ENBOX_TOOL_LOG_FACILITY`
* :c:macro:`CONFIG_ENBOX_TOOL_MQLOG_NAME`
  
Usage
=====

Enbox_ library API is organized around the following functional areas which
you can refer to for further details :

* Initialization_,
* Configuration_,
* Instantiation_,
* and Utilities_.

The typical sequence of operations involves using the first 3 functional
areas mentioned above. Most of the time, you use Enbox_ library in one of the
2 following ways :

* `Run a configuration from filesystem`_
* or `Run a configuration from hard-coded values`_.

Run a configuration from filesystem
-----------------------------------

This mode of operation is meant to apply and execute an Enbox_ configuration
stored into a file. This file must be formatted according to the
configuration syntax detailed into the :ref:`sect-main-configuration` section.

Additional usage details may be found into section Configuration_. This
is the most straightforward way to use the Enbox_ library.

Run a configuration from hard-coded values
------------------------------------------

This mode of operation is meant to apply and execute an Enbox_ configuration
from pre-defined hard-coded values found into multiple binary structures
built at compile-time.

Additional usage details may be found into section Instantiation_. This is the
most complex way to use the Enbox_ library.

Initialization
==============

Using Enbox_ library requires to initialize it first using :

* :c:func:`enbox_setup`

Configuration
=============

Configuration directives may be used to setup Enbox_ library runtime behavior.
Refer to the :ref:`usage configuration <sect-main-configuration>` section for
additional informations.

Configuration workflow involves the following typical sequence of operations :

#. initialize Enbox_ library using :c:func:`enbox_setup`,
#. load and parse an Enbox_ configuration from the content of a file using
   :c:func:`enbox_create_conf_from_file`,
#. apply and execute the configuration loaded above using
   :c:func:`enbox_run_conf`.

Calling :c:func:`enbox_run_conf` will not return to caller if the configuration
specifies a command to |execve(2)|. See section Instantiation_ and
:c:func:`enbox_run_cmd` for more informations about this.
   
In any other cases, a call to :c:func:`enbox_run_conf` will return to caller
wether the configuration was successfully applied or not and one should call
:c:func:`enbox_destroy_conf` to release resources allocated by 
:c:func:`enbox_create_conf_from_file`.

Note that :c:type:`enbox_conf` is an opaque structure holding a loaded Enbox_
configuration that may be required by functions mentioned above.

.. todo:: 

   Add configuration API sample code

Instantiation
=============

Enbox_ library runtime behavior may also be setup from a pre-defined set of
hard-coded values. This is the most flexible and complex way to use the library.

Support for the following tasks is implemented :

* :ref:`sect-populate_host_fs`,
* :ref:`sect-usr_grp_ids`,
* :ref:`sect-setup_proc`,
* :ref:`sect-spawn_jail`,
* :ref:`sect-subseq_ops`.

These tasks may be combined to implement multiple `Use cases`_ described below.

.. todo:: 

   Add Instantiation API sample code

.. _sect-populate_host_fs:

Populate host filesystem
------------------------

A «host» filesystem hierarchy may be required to exist prior to
:ref:`performing subsequent operations <sect-subseq_ops>`.

The host may be populated with filesystem entries thanks to
:c:func:`enbox_populate_host` allowing to create any arbitrary hierarchy.
:c:type:`enbox_fsset` is the structure that conveys filesystem entry
specifications.

.. _sect-usr_grp_ids:

Manage user and groups
----------------------

Optionally, system user ownership and group membership informations are used
to :

* initialize the root filesystem of a :ref:`spawned jail <sect-spawn_jail>` ;
* switch to user and group identifiers before
  :ref:`performing subsequent operations <sect-subseq_ops>`.

:c:func:`enbox_load_ids_byid` and :c:func:`enbox_load_ids_byname` load user and
group informations into an opaque :c:type:`enbox_ids` structure which is
further required to achieve the 2 tasks mentioned above.

.. _sect-setup_proc:

Setup process
-------------

To secure further operations, Enbox_ provides the ability to restrict system
privileges for the current process thanks to the :c:func:`enbox_prep_proc`
function.

The caller may enforce the following properties for the current process thanks
to the :c:type:`enbox_proc` structure:

* |umask|,
* |capabilities|,
* |cwd|,
* and the closing of unwanted file descriptors.

In addition, the :c:func:`enbox_prep_proc` function may also spawn and enter a
|jail| to further restrict accesses of current proces to global system
resources.

.. _sect-spawn_jail:

Spawn a jail
------------

Spawning a jail is meant to instantiate a runtime container providing isolation
from the main system-wide «host» runtime. A program may be further
|execve(2)|'ed from within this newly created jail, restricting all accesses to
global system resources in a configurable way.
As stated into section `Overview`_, isolation implementation is based upon Linux
|namespaces(7)| and |capabilities(7)|.

When given a non `NULL` :c:type:`enbox_jail` argument, the
c:func:`enbox_prep_proc` function creates a new jail and jumps into it.
Once entered, there is no more way to escape it apart from calling |exit(3)|,
which will implictly destroy the jail.

Jail is instantiated according to properties set into the :c:type:`enbox_jail`
structure allowing to specify :

* set of new |namespaces(7)| to make the jail a member of,
* and jail's root filesystem content.

Note that filesystem content specification mechanism provides the ability to
«import» or «share» entries with the «host» thanks to Linux bind mount
mechanism. See :c:type:`enbox_bind_entry` structure for additional informations
about this.

.. _sect-subseq_ops:

Subsequent operations
---------------------

Once the current :ref:`process privileges <sect-setup_proc>` have been
restricted (and eventually :ref:`jailed <sect-spawn_jail>`), one can proceed to
further operations in a secure manner thanks to one of the following functions:

* :c:func:`enbox_run_proc_cmd`
* :c:func:`enbox_change_proc_ids`.

If requested, :c:func:`enbox_change_proc_ids` changes current user / group IDs
and hands back controll to the caller. :c:func:`enbox_run_proc_cmd` may in
addition |execve(2)| an arbitrary program.

When requested, subsequent operations will run under the system user and groups
given into a :c:type:`enbox_ids` structure previously loaded as explained into
`sect-usr_grp_ids` section.
In addition, both functions drop |capabilities(7)| inherited from parent process
according to the :c:type:`enbox_proc` structure to complete isolation from
«host».

Utilities
=========

Enbox_ library also exposes various utility functions used to implement logics
mentioned above. These are :

.. hlist::

   * Processes :

      * :c:func:`enbox_change_idsn_execve`,
      * :c:func:`enbox_execve`,
      * :c:func:`enbox_get_umask`,
      * :c:type:`enbox_jail`,
      * :c:func:`enbox_prep_proc`,
      * :c:type:`enbox_proc`,
      * :c:func:`enbox_run_proc_cmd`,
      * :c:func:`enbox_set_umask`,

   * User / group IDs :

      * :c:func:`enbox_change_ids`,
      * :c:func:`enbox_change_idsn_execve`,
      * :c:func:`enbox_change_proc_ids`,
      * :c:func:`enbox_get_uid`,
      * :c:func:`enbox_get_gid`,
      * :c:type:`enbox_ids`,
      * :c:func:`enbox_switch_ids`,

   * Capabilities :

      * :c:macro:`ENBOX_CAP`,
      * :c:func:`enbox_cap`,
      * :c:func:`enbox_clear_amb_caps`,
      * :c:func:`enbox_clear_bound_caps`,
      * :c:func:`enbox_clear_epi_caps`,
      * :c:func:`enbox_enforce_safe`,
      * :c:func:`enbox_ensure_safe`,

   * Filesystem :

      * :c:func:`enbox_change_perms`,
      * :c:func:`enbox_make_blkdev`,
      * :c:func:`enbox_make_chrdev`,
      * :c:func:`enbox_make_dir`,
      * :c:func:`enbox_make_fifo`,
      * :c:func:`enbox_make_slink`,

   * Various :

      * :c:func:`enbox_show_status`

Use cases
=========

sshd
----

Sshd process architecture:

* 1 *master* process that listens connection on main port (22) and running as
  *root* ;
* 1 *privileged monitor* process, ``/usr/libexec/sshd-session``, running as
  *root* and that executes the PAM handshake and |fork(2)| the *unprivileged
  monitor* ;
* 1 *unprivileged monitor* process, ``/usr/libexec/sshd-session``, 
  that switches immediatly to final user ID and |fork(2)| / |execve(2)| the
  final *unprivileged shell* process ;
* 1 *unprivileged shell* process running as final user ID.

Session establishment workflow:

#. upon connection request, *master* process |fork(2)| / |execve(2)| the
   *privileged monitor*
#. *privileged monitor* run the PAM handshake then |fork(2)| the *unprivileged
   monitor*
#. *unprivileged monitor* changes to final user ID then |fork(2)| / |execve(2)|
   final user *unprivileged shell*.

For more informations, refer to :

`OpenSSH Sandboxing and Privilege Separation <https://jfrog.com/blog/examining-openssh-sandboxing-and-privilege-separation-attack-surface-analysis>`_
`Privilege Separated OpenSSH <http://www.citi.umich.edu/u/provos/ssh/privsep.html>`_

.. rubric:: with pre-opened listen socket(s)

#. setup host rootfs and open listen socket(s)
#. setup jail rootfs with *root* user primary group ID and a chroot directory
   for cli user usage (see ``ChrootDirectory`` option)
#. enter jail with its own namepaces
#. |execve(2)| sshd as *root* user with the following capabilities:

   * sys_chroot
   * setuid
   * setgid
   * chown
   * fowner
   * kill

#. Make sure that inherited and ambient capabilities are cleared during
   *privileged monitor* PAM handshake operations, i.e., before *unprivileged
   monitor* switches to final user ID.


.. rubric:: without pre-opened listen socket(s)

#. setup host rootfs
#. setup jail rootfs with *root* user primary group ID and a chroot directory
   for cli user usage (see ``ChrootDirectory`` option)
#. enter jail with its own namespaces except *net*
#. |execve(2)| sshd as *root* user with the following capabilities:
   
   * net_bind_service
   * sys_chroot
   * setuid
   * setgid
   * chown
   * fowner
   * kill

#. Make sure that inherited and ambient capabilities are cleared during
   *privileged monitor* PAM handshake operations, i.e., before *unprivileged
   monitor* switches to final user ID.

lighttpd
--------

.. rubric:: with pre-opened listen socket(s)

#. setup host rootfs and open listen socket(s)
#. setup jail rootfs with lighttpd user /group IDs
#. enter jail with its own namepaces
#. |execve(2)| lighttpd as lighttpd user with no capabilities

Note that in this case, lighttpd looses the ability to |chroot(8)| into web
documents root directory !

.. rubric:: without pre-opened listen socket(s)

#. setup host rootfs
#. setup jail rootfs with *lighttpd* user primary group ID
#. enter jail with its own namespaces except *net*
#. |execve(2)| lighttpd as root and request it to switch to *lighttpd* user with
   the following capabilities:
   
   * setuid
   * setgid
   * net_bind_service
   * sys_chroot

#. Make sure that inherited and ambient capabilities are cleared before PAM
   operations

elogd
-----

.. rubric:: without pre-opened kernel logging ring-buffer
   
.. todo:: complete me!


.. rubric:: with pre-opened kernel logging ring-buffer

.. todo:: complete me!

PAM module
----------

Typical use case involves a standard login process onto console through PAM. The
Enbox_ PAM module setup the jail at PAM session establishment for final user
shell containment.

#. ``login`` manages authentication over the console, running as *root*
   
   
like so:

#. setup host rootfs
#. setup jail rootfs with final user primary group ID
#. enter jail with its own namespaces except *net*
#. |execve(2)| lighttpd as root and request it to switch to *lighttpd* user with
   the following capabilities:
   
   * setuid
   * setgid
   * net_bind_service
   * sys_chroot

#. Make sure that inherited and ambient capabilities are cleared before PAM
   operations



Reference
=========

Configuration macros
--------------------

CONFIG_ENBOX_ASSERT
*******************

.. doxygendefine:: CONFIG_ENBOX_ASSERT

CONFIG_ENBOX_VERBOSE
********************

.. doxygendefine:: CONFIG_ENBOX_VERBOSE

CONFIG_ENBOX_DEBUG
******************

.. doxygendefine:: CONFIG_ENBOX_DEBUG

CONFIG_ENBOX_INCLUDE_DIR
************************

.. doxygendefine:: CONFIG_ENBOX_INCLUDE_DIR

CONFIG_ENBOX_DISABLE_DUMP
*************************

.. doxygendefine:: CONFIG_ENBOX_DISABLE_DUMP

CONFIG_ENBOX_SHOW
*****************

.. doxygendefine:: CONFIG_ENBOX_SHOW

CONFIG_ENBOX_TOOL
*****************

.. doxygendefine:: CONFIG_ENBOX_TOOL

CONFIG_ENBOX_TOOL_LOG_FACILITY
******************************

.. doxygendefine:: CONFIG_ENBOX_TOOL_LOG_FACILITY

CONFIG_ENBOX_TOOL_LOG_SEVERITY
******************************

.. doxygendefine:: CONFIG_ENBOX_TOOL_LOG_SEVERITY

CONFIG_ENBOX_TOOL_MQLOG_NAME
****************************

.. doxygendefine:: CONFIG_ENBOX_TOOL_MQLOG_NAME
   
Macros
------

ENBOX_CAP
*********

.. doxygendefine:: ENBOX_CAP

ENBOX_DROP_SUPP_GROUPS
**********************

.. doxygendefine:: ENBOX_DROP_SUPP_GROUPS

ENBOX_KEEP_GID
**************

.. doxygendefine:: ENBOX_KEEP_GID

ENBOX_KEEP_MODE
***************

.. doxygendefine:: ENBOX_KEEP_MODE

ENBOX_KEEP_UID
**************

.. doxygendefine:: ENBOX_KEEP_UID

ENBOX_NAMESPACE_FLAGS
*********************

.. doxygendefine:: ENBOX_NAMESPACE_FLAGS

ENBOX_RAISE_SUPP_GROUPS
***********************

.. doxygendefine:: ENBOX_RAISE_SUPP_GROUPS

Enumerations
------------

enbox_entry_type
****************

.. doxygenenum:: enbox_entry_type

Structures
----------

.. todo::

   Document struct elog (intersphinx)

enbox_bind_entry
****************

.. doxygenstruct:: enbox_bind_entry

enbox_conf
**********

.. doxygenstruct:: enbox_conf

enbox_dev_entry
***************

.. doxygenstruct:: enbox_dev_entry

enbox_dir_entry
***************

.. doxygenstruct:: enbox_dir_entry

enbox_entry
***************

.. doxygenstruct:: enbox_entry

enbox_fifo_entry
****************

.. doxygenstruct:: enbox_fifo_entry

enbox_fsset
***********

.. doxygenstruct:: enbox_fsset

enbox_ids
*********

.. doxygenstruct:: enbox_ids

.. todo::

   Hide struct enbox_conf internal fields

enbox_jail
**********

.. doxygenstruct:: enbox_jail

enbox_mount_entry
*****************

.. doxygenstruct:: enbox_mount_entry

enbox_proc
**********

.. doxygenstruct:: enbox_proc

enbox_slink_entry
*****************

.. doxygenstruct:: enbox_slink_entry

Functions
---------

enbox_cap()
***********

.. doxygenfunction:: enbox_cap

enbox_change_ids()
******************

.. doxygenfunction:: enbox_change_ids

enbox_change_idsn_execve()
**************************

.. doxygenfunction:: enbox_change_idsn_execve

enbox_change_proc_ids
*********************

.. doxygenfunction:: enbox_change_proc_ids

enbox_change_perms()
********************

.. doxygenfunction:: enbox_change_perms

enbox_clear_amb_caps()
**********************

.. doxygenfunction:: enbox_clear_amb_caps

enbox_clear_bound_caps()
************************

.. doxygenfunction:: enbox_clear_bound_caps

enbox_clear_epi_caps()
************************

.. doxygenfunction:: enbox_clear_epi_caps

enbox_create_conf_from_file()
*****************************

.. doxygenfunction:: enbox_create_conf_from_file

enbox_destroy_conf()
********************

.. doxygenfunction:: enbox_destroy_conf

enbox_enforce_safe()
********************

.. doxygenfunction:: enbox_enforce_safe

enbox_ensure_safe()
*******************

.. doxygenfunction:: enbox_ensure_safe

enbox_execve()
**************

.. doxygenfunction:: enbox_execve

enbox_get_gid()
***************

.. doxygenfunction:: enbox_get_gid

enbox_get_umask()
*****************

.. doxygenfunction:: enbox_get_umask

enbox_get_uid()
***************

.. doxygenfunction:: enbox_get_uid

enbox_load_ids_byid()
*********************

.. doxygenfunction:: enbox_load_ids_byid

enbox_load_ids_byname()
***********************

.. doxygenfunction:: enbox_load_ids_byname

enbox_make_blkdev()
*******************

.. doxygenfunction:: enbox_make_blkdev

enbox_make_chrdev()
*******************

.. doxygenfunction:: enbox_make_chrdev

enbox_make_dir()
****************

.. doxygenfunction:: enbox_make_dir

enbox_make_fifo()
*****************

.. doxygenfunction:: enbox_make_fifo

enbox_make_slink()
******************

.. doxygenfunction:: enbox_make_slink

enbox_populate_host()
*********************

.. doxygenfunction:: enbox_populate_host

enbox_prep_proc
***************

.. doxygenfunction:: enbox_prep_proc

enbox_run_conf()
****************

.. doxygenfunction:: enbox_run_conf

enbox_run_proc_cmd
******************

.. doxygenfunction:: enbox_run_proc_cmd

enbox_set_umask()
*****************

.. doxygenfunction:: enbox_set_umask

enbox_setup()
*************

.. doxygenfunction:: enbox_setup

enbox_show_status()
*******************

.. doxygenfunction:: enbox_show_status

enbox_switch_ids()
******************

.. doxygenfunction:: enbox_switch_ids
