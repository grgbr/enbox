.. include:: _cdefs.rst

.. _sect-api_overview:

Overview
========

What follows here provides a thorough description of how to use Enbox's library.
Please, head to sections :ref:`sect-top-overview` and
:ref:`sect-top-terminology` for an introduction to Enbox concepts.

Basically, Enbox library is the C framework that lies underneath Enbox. It is
provided to carry out Enbox related tasks directly from C/C++ applications.

In addition to a high-level functional API, the library also comes with
additional utility functions allowing to manipulate Linux system objects in a
limited way. See section Utilities_ for more informations.

Usage
=====

Enbox library API is organized around the following functional areas which
you can refer to for further details :

* Initialization_,
* Configuration_,
* Instantiation_,
* and Utilities_.

The typical sequence of operations involves using the first 3 functional
areas mentioned above. Most of the time, you use Enbox library in one of the
2 following ways :

* `Run a configuration from filesystem`_
* or `Run a configuration from hard-coded values`_.

Run a configuration from filesystem
-----------------------------------

This mode of operation is meant to apply and execute an Enbox configuration
stored into a file. This file must be formatted according to the
configuration syntax detailed into the :ref:`sect-usage_conf` section.

Additional usage details may be found into section Configuration_. This
is the most straightforward way to use the Enbox library.

Run a configuration from hard-coded values
------------------------------------------

This mode of operation is meant to apply and execute an Enbox configuration
from pre-defined hard-coded values found into multiple binary structures
built at compile-time.

Additional usage details may be found into section Instantiation_. This is the
most complex way to use the Enbox library.

Initialization
==============

Using Enbox library requires to initialize it first using :

* :c:func:`enbox_setup`

Configuration
=============

Configuration directives may be used to setup Enbox library runtime behavior.
Refer to the :ref:`usage configuration <sect-usage_conf>` section for
additional informations.

Configuration workflow involves the following typical sequence of operations :

#. initialize Enbox library using :c:func:`enbox_setup`,
#. load and parse an Enbox configuration from the content of a file using
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

Note that :c:type:`enbox_conf` is an opaque structure holding a loaded Enbox
configuration that may be required by functions mentioned above.

.. todo:: 

   Add configuration API sample code

Instantiation
=============

Enbox library runtime behavior may also be setup from a pre-defined set of
hard-coded values. This is the most flexible and complex way to use the library.

Support for the following tasks is implemented :

* :ref:`sect-populate_host_fs`,
* :ref:`sect-usr_grp_ids`,
* :ref:`sect-spawn_jail`,
* :ref:`sect-run_cmd`.

These tasks may be combined to implement multiple `Use cases`_ described below.

.. todo:: 

   Add Instantiation API sample code

.. _sect-populate_host_fs:

Populate host filesystem
------------------------

A «host» filesystem hierarchy may be required to exist prior to
:ref:`running a command <sect-run_cmd>`.

The host may be populated with filesystem entries thanks to
:c:func:`enbox_populate_host` allowing to create any arbitrary hierarchy.
:c:type:`enbox_fsset` is the structure that conveys filesystem entry
specifications.

.. _sect-usr_grp_ids:

Manage user and groups
----------------------

System user ownership and group membership informations are required to :

* initialize the root filesystem of a :ref:`spawned jail <sect-spawn_jail>` ;
* switch to user and group identifiers before
  :ref:`running a command <sect-run_cmd>`.

:c:func:`enbox_load_ids_byid` and :c:func:`enbox_load_ids_byname` load user and
group informations into an opaque :c:type:`enbox_ids` structure which is
further required to achieve the 2 tasks mentioned above.

.. _sect-spawn_jail:

Spawn a jail
------------

Spawning a jail is meant to instantiate a runtime container providing isolation
from the main system-wide «host» runtime. A program may be further
|execve(2)|'ed from within this newly created jail, restricting all accesses to
global system resources in a configurable way.
As stated into section `Overview`_, isolation implementation is based upon Linux
|namespaces(7)| and |capabilities(7)|.

The :c:func:`enbox_enter_jail` function creates a new jail and jumps into it.
Once entered, there is no more way to escape it apart from calling |exit(2)|,
which will implictly destroy the jail.
All priviledges, i.e. |capabilities(7)|, inherited from parent process will be
dropped when running the program to isolate from «host», at next call to
|execve(2)|. See section :ref:`sect-run_cmd` for additional informations about
running a command with Enbox.

Jail is instantiated according to properties set into a :c:type:`enbox_jail`
structure allowing to specify among other things :

* set of new |namespaces(7)| to make the jail a member of,
* and jail's root filesystem content.

Note that filesystem content specification mechanism provides the ability to
«import» or «share» entries with the «host» thanks to Linux bind mount
mechanism. See :c:type:`enbox_bind_entry` structure for additional informations
about this.

.. _sect-run_cmd:

Run a command
-------------

Basically |execve(2)| a command under specified system user / groups
identifiers. It also provides the ability to set additional runtime context
properties such as process file mode creation mask, current working directory,
program arguments, etc...

The :c:func:`enbox_load_ids_byid` function `execve(2)_` a command specified by
the content of a :c:type:`enbox_cmd` structure.

The program will run under the system user and groups given into a
:c:type:`enbox_ids` structure previously loaded as explained into
`sect-usr_grp_ids` section.

Although not mandatory, the command may optionally be executed from within a
:ref:`jail <sect-spawn_jail>`, in which case system priviledges are dropped at
|execve(2)| time.

Utilities
=========

Enbox library also exposes various utility functions used to implement logics
mentioned above. These are :

.. hlist::

   * Processes :
     
      * :c:func:`enbox_setup_dump`,
      * :c:func:`enbox_get_umask`,
      * :c:func:`enbox_set_umask`,

   * User / group IDs :
     
      * :c:func:`enbox_change_ids`,
      * :c:func:`enbox_get_uid`,
      * :c:func:`enbox_get_gid`,
        
   * Capabilities :
     
      * :c:func:`enbox_clear_ambient_caps`
      * :c:func:`enbox_clear_bounding_caps`
      * :c:func:`enbox_lock_caps`
        
   * Filesystem :
     
      * :c:func:`enbox_change_perms`,
      * :c:func:`enbox_make_blkdev`,
      * :c:func:`enbox_make_chrdev`,
      * :c:func:`enbox_make_dir`,
      * :c:func:`enbox_make_fifo`,
      * :c:func:`enbox_make_slink`,

Use cases
=========

.. todo::

   Document typical API use cases

Reference
=========

Macros
------

ENBOX_DISABLE_DUMP
******************

.. doxygendefine:: ENBOX_DISABLE_DUMP

ENBOX_DROP_SUPP_GROUPS
**********************

.. doxygendefine:: ENBOX_DROP_SUPP_GROUPS

ENBOX_ENABLE_DUMP
*****************

.. doxygendefine:: ENBOX_ENABLE_DUMP

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

enbox_cmd
*********

.. doxygenstruct:: enbox_cmd

enbox_conf
**********

.. doxygenstruct:: enbox_conf

.. todo::

   Hide struct enbox_conf internal fields

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

   Hide struct enbox_ids internal fields

enbox_jail
**********

.. doxygenstruct:: enbox_jail

enbox_mount_entry
*****************

.. doxygenstruct:: enbox_mount_entry

enbox_slink_entry
*****************

.. doxygenstruct:: enbox_slink_entry

Functions
---------

enbox_change_ids()
******************

.. doxygenfunction:: enbox_change_ids

enbox_change_perms()
********************

.. doxygenfunction:: enbox_change_perms

enbox_clear_ambient_caps()
**************************

.. doxygenfunction:: enbox_clear_ambient_caps

enbox_clear_bounding_caps()
***************************

.. doxygenfunction:: enbox_clear_bounding_caps

enbox_create_conf_from_file()
*****************************

.. doxygenfunction:: enbox_create_conf_from_file

enbox_destroy_conf()
********************

.. doxygenfunction:: enbox_destroy_conf

enbox_enter_jail()
******************

.. doxygenfunction:: enbox_enter_jail

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

enbox_lock_caps()
*****************

.. doxygenfunction:: enbox_lock_caps

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

enbox_run_cmd()
***************

.. doxygenfunction:: enbox_run_cmd

enbox_run_conf()
****************

.. doxygenfunction:: enbox_run_conf

enbox_set_umask()
*****************

.. doxygenfunction:: enbox_set_umask

enbox_setup()
*************

.. doxygenfunction:: enbox_setup

enbox_setup_dump()
******************

.. doxygenfunction:: enbox_setup_dump
