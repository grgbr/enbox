.. include:: _cdefs.rst

.. _sect-main-overview:

Overview
========

Enbox_'s primary goal is to secure processes running onto Linux based systems.

Simply put, Enbox_ provides a way to run a Linux process in an isolated runtime
environment which we call a |jail|. This runtime container confers the ability
to control the process accesses to system resources according to a predefined
configuration.

Thanks to Enbox_, a process gains additional security since isolated from all
other processes on the |host| machine. In addition, the whole system is
hardened against software vulnerabilities since processes may be run with
restricted privileges.

Enbox_ ships with a :ref:`binary tool <usage>` and a
:ref:`library <sect-api-overview>`.
The :ref:`enbox tool <usage>` allows system administrators to setup and
instantiate processes according to settings stored into dedicated configuration_
files.
The :ref:`library <sect-api-overview>`, which the :ref:`enbox tool <usage>` is
based upon, provides developpers with a way to carry out Enbox_ related tasks
directly from their own code.

.. _sect-main-terminology:

Terminology
===========

Using Enbox_ involves setting up multiple kind of objects. These are described
in the following sections.

.. _sect-main-jail:

Jail
----

A runtime container from within which a process runs isolated from all other
processes on the |host| machine. Once all jail'ed (possibly child) processes
have |exit(2)|'ed, the container is destroyed and all its allocated resources
are released by the kernel.

Enbox_ allows you to control how isolated a jail is from global system
resources, other processes and jails on the |host| machine. The underlying
containment logic is based upon Linux's |namespaces|, |capabilities| and
|credentials| switching mechanisms.

Depending on the jail'ed process expectations, the jail may require |host| and
/ or jail filesystem images to properly run. Enbox_ allows you to define and
populate both |host| and jail'ed filesystem hierarchies.

You may think of a |jail| as an extended version of |chroot(8)| with additional
isolation not available when simply using it. In addition, Enbox_ ease
the process of preparing the |chroot(8)| filesystem image by combining 2 Linux
kernel features:

* |mount_namespaces(7)|
* and |bind mount|.

|host| side filesystem hierarchies may be imported into jail using the |bind
mount| machinery. These mounts are performed from within the jail's own mount
namespace (see |mount_namespaces(7)|) and are implitcly released once the jail
dies.

.. _sect-main-host:

Host
----

The hardware machine the initial OS is running on.
Thanks to Linux OS services, Enbox_ allows you to define and dedicate subsets of
|host| resources to be shared with a |jail|.

Depending on |jail|'s expectations, you may need to populate the host filesystem
with entries that may later be imported into the |jail|. This is also the
mechanisms used to share filesystem content between the host and a |jail|.

These filesystem entries are persistent from the |jail|'s point of view, i.e
removal of entries is delegated to system administration tasks.

.. _sect-main-credentials:

Credentials
-----------

A set of identifiers described into section `User and group identifiers` of
|credentials(7)|, namely:

* |uid|,
* |gid|,
* |supplementary groups|.

When switching to a pre-configured set of identifiers, Enbox_ drops inherited
privileges of current process.

When combined with |capabilities| management, this mechanism allows Enbox_ to
enforce permanent strong privilege restrictions.

.. _sect-main-capabilities:

Capabilities
------------

Privilege restriction relies upon the Linux capability mechanism. As stated
into |capabilities(7)|:

    [...] Linux divides the privileges traditionally associated with superuser
    into distinct units, known as capabilities, which can be independently
    enabled and disabled.

Enbox_ ensures that all capabilities are dropped when switching to a
non-privileged user (using |setresuid(2)|) and at |execve(2)| time.

.. _sect-main-namespaces:

Namespaces
----------

The container logic implementation is based upon Linux's namespaces. As stated
into |namespaces(7)|:

    A namespace wraps a global system resource in an abstraction that makes
    it appear to the processes within the namespace that they have their own
    isolated instance of the global resource. Changes to the global resource
    are visible to other processes that are members of the namespace, but
    are invisible to other processes.

More specifically, Enbox_ handles the following types of namespace:

* |mount_namespaces(7)|,
* |cgroup_namespaces(7)|,
* `UTS` namespaces (see |namespaces(7)|),
* `IPC` namespaces (see |namespaces(7)|),
* and |network_namespaces(7)|.

Enbox_ is mainly designed to run onto embedded systems, i.e., from within a
controlled software runtime. That is the reason why Enbox_ is a |execve(2)| based
containment system only (to keep things simple and lightweight). As a
consequence, this comes with a few limitations with respect to namespace
isolation handling:

* |pid_namespaces(7)| are not supported since we don't want to handle fork /
  init process machinery ; instead, we may rely upon secure |procfs(5)|
  operations to provide some sort of |pid| space isolation (see |procfs(5)|
  hidepid / gid / subset mount options) ;
* |user_namespaces(7)| are not supported either since we don't really need it
  for now (we have no use case for emulating a complete virtualized OS while
  running onto an embedded system).

Features
========

* optional process isolation thanks to |namespaces|
* optional privileges restriction  thanks to |capabilities| and |credentials|
* manage filesystem objects
* |execve(2)| based, i.e., no |fork(2)| support
* no |pid| space isolation although |procfs(5)| based restriction may apply
* no |uid| / |gid| space isolation
* lightweight
* Linux OS only

.. _usage:

Usage
=====

.. todo::

   Document enbox tool usage

.. _sect-main-configuration:

Configuration
=============

Configuration is stored in an ASCII text file that contains a structured and
hierarchical sequence of statements parsed using the `libconfig library`_.

Conventions
-----------

The file may contain extra *spaces*, *tabulations* and *newlines* for formatting
purposes. Keywords are *case-sensitive*.
*Comments* may be placed anywhere within the file (except within quotes).
Comments begin with the ``#`` character and end at the end of the line.

Configuration file grammar is inspired by the `utility conventions`_ defined
into the `IEEE Std 1003.1`_ POSIX specification:

* literals are enclosed within single quotes, i.e. ``'`` ;
* expressions surrounded by angle brackets, i.e. ``<`` and ``>``, require
  substitution ;
* expressions enclosed within brackets, i.e. ``[`` and ``]``, are optional ;
* expressions separated by a vertical line, i.e. ``|``, are mutually exclusive ;
* when followed by ellipses, i.e. ``...``, one or more occurrences of an
  expression are allowed ;
* expressions enclosed within parentheses, i.e. ``(`` and ``)``, are grouped
  together.

.. _libconfig-types:

.. topic:: Elementary types

   The following predefined non-terminal production rules are used throughout
   this document and refer to the corresponding `libconfig library`_ types.
   Please head to the `libconfig manual`_ to refer to related definitions. These
   are:

   * the *boolean* type <`BOOL <libconfig-bool_>`_>,
   * the *string* type <`STRING <libconfig-string_>`_>.

.. _syntax-sep:

.. topic:: Separators

   In addition, the following syntax token separators are used in production
   rules. These are defined as:

   .. parsed-literal::
      :class: highlight

      <**LF**>   ::= '\\n'                    *; line feed*
      <**LSEP**> ::= ',' [<**LF**>]...           *; list separator*
      <**SSEP**> ::= ';' [<**LF**>]... | <**LF**>... *; group setting separator*

Grammar
-------

Configuration essentially consists of a list of statements. It shall start with
at least one of the top-level statements according to the following syntax.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**config**> ::= [<`top-host`_>] [<`top-ids`_> [<`top-jail`_>] <`top-cmd`_>]

Each top-level statement configures a subset of the Enbox_ behavior as described
below:

* `top-host`_ statement relates to host filesystem content ;
* `top-ids`_ statement relates to system user and group identifiers ;
* `top-jail`_ statement relates to containment logic ;
* `top-cmd`_: statement relates to program execution.

.. rubric:: Example

.. code-block::

   # Populate the host filesystem
   host = (
        ...
   )

   # Load system user and group identifiers
   ids = {
        ...
   }

   # Containment logic settings
   jail = {
        ...
   }

   # Program execution settings
   cmd = {
        ...
   }

Reference
---------

caps-attr
*********

Within the context of a `top-cmd`_ statement, specify the list of system
|capabilities(7)| to run the command process with.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**caps-attr**> ::= 'caps = [' <caps-list> ']'
   <**caps-list**> ::= '"' <**cap**> '"' [|LSEP| '"' <**cap**> '"']...
   <**cap**>       ::= 'chown'
                 | 'dac_override'
                 | 'dac_read_search'
                 | 'fowner'
                 | 'fsetid'
                 | 'kill'
                 | 'setgid'
                 | 'setuid'
                 | 'linux_immutable'
                 | 'net_bind_service'
                 | 'net_broadcast'
                 | 'net_admin'
                 | 'net_raw'
                 | 'ipc_lock'
                 | 'ipc_owner'
                 | 'sys_module'
                 | 'sys_rawio'
                 | 'sys_chroot'
                 | 'sys_ptrace'
                 | 'sys_pacct'
                 | 'sys_boot'
                 | 'sys_nice'
                 | 'sys_resource'
                 | 'sys_time'
                 | 'sys_tty_config'
                 | 'mknod'
                 | 'lease'
                 | 'audit_write'
                 | 'audit_control'
                 | 'setfcap'
                 | 'mac_override'
                 | 'mac_admin'
                 | 'syslog'
                 | 'wake_alarm'
                 | 'block_suspend'
                 | 'audit_read'
                 | 'perfmon'
                 | 'bpf'
                 | 'checkpoint_restore'

This attribute is *optional*.

.. important::
   For obvisous security reasons, the propagation of ``CAP_SETPCAP`` and
   ``CAP_SYS_ADMIN`` capabilities are rejected.

.. rubric:: Example

.. code-block::

   # Run command process with CAP_NET_BIND_SERVICE and CAP_NET_RAW
   # capabilities(7)
   cmd = {
           ...
           caps = [ "net_bind_service", "net_raw" ]
   }

cwd-attr
********

Within the context of a `top-cmd`_ statement, specify the |cwd| to run the
command process with.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**cwd-attr**> ::= 'cwd = "' <|pathname|> '"'

This attribute is optional and *defaults* to ``"/"`` when unspecified.

.. rubric:: Example

.. code-block::

   # Load system user and groups
   cmd = {
           ...
           cwd = "/var/lib/mydaemon"
   }

drop-supp-attr
**************

Within the context of a `top-ids`_ statement, specify wether to drop
|supplementary groups| from the group access list or not.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**drop-supp-attr**> ::= 'drop_supp =' |BOOL|

|supplementary groups| are dropped if ``true`` and loaded otherwise.
**drop-supp-attr** *defaults* to ``false`` when unspecified.

Note that group access list will always contain the user's primary group.

.. rubric:: Example

.. code-block::

   # Load system user and groups
   ids = {
           # System user and its (implicit) related primary group
           user = "myuser"
           # Load supplementary groups myuser is a member of.
           drop_supp = false
   }

exec-attr
*********

Within the context of a `top-cmd`_ statement, specify the command program and
arguments to |execve(2)|.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**exec-attr**> ::= 'exec = [' <|pathname|> [|LSEP| <exec-arg> ]... ']'
   <**exec-arg**>  ::= '"' |STRING| '"'

This attribute is *mandatory*.

.. rubric:: Example

.. code-block::

   # Load system user and groups
   cmd = {
           ...
           exec = [ "/sbin/mydaemon", "--opt", "value" ]
   }

fs-bind-opts
************

Customize filesystem specific |bind mount| properties.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-bind-opts**>  ::= 'opts = "' <**fs-mount**opts**> '"'
   <**fs-mount-opts**> ::= |STRING| [',' |STRING|]...

Setup filesystem specific options when making a |host| filesystem entry visible
from within a |jail| using fs-file_ or fs-tree_ statements.
Value **fs-mount-opts** is passed as-is as fifth argument to |mount(2)| when
|bind mount|'ing the original |host| filesystem entry into the |jail|.

This must be a string of *comma-separated options* understood by the *underlying
filesystem* hosting the entry to be imported into the |jail|. Options taken into
account are the *per-mount* options only. See |mount(8)| for details of the
options available for each filesystem type.

This attribute is optional and *defaults* to none when unspecified.

.. rubric:: Example

.. code-block::
   :emphasize-lines: 12,13,14

   # Define a jail
   jail = {
           ...
           # Setup jail's filesystem content
           fsset = (
                   ...
                   { # Import /lib host sub-tree into jail
                           type  = "tree"
                           path  = "lib"
                           orig  = "/lib"
                           flags = [ "ro", "nodev", "nosuid", "noatime" ]
                           # Bind mount with UBIFS specific options since host
                           # /lib sub-tree is stored onto an UBIFS filesystem.
                           opts  = "bulk_read,no_chk_data_crc"
                   },
                   ...
           )
   }

fs-blkdev
*********

Define a filesystem block device file entry.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-blkdev**> ::= 'type = "blkdev"'
                   |SSEP| <`fs-path-attr`_>
                   |SSEP| <`fs-mode-attr`_>
                   |SSEP| <`fs-major-attr`_>
                   |SSEP| <`fs-minor-attr`_>
                   [|SSEP| <`user-attr`_>]
                   [|SSEP| <`group-attr`_>]

Use fs-path-attr_ to specify the pathname to the block device file to create.
Use fs-mode-attr_ to specify its |file mode bits|.
Use fs-major-attr_ and fs-minor-attr_ to specify its |fs-major| and |fs-minor|
numbers respectively.
Attributes mentioned above are *mandatory*.

You may specify the block device file owner thanks to user-attr_. This attribute
is optional and *defaults* to the current |effective user| when unspecified.

You may also specify the block device file group membership thanks to
group-attr_. This attribute is optional and *defaults* to the current |effective
group| when unspecified.

.. rubric:: Example

.. code-block::

   # Define a loopback block device file
   {
           type  = "blkdev"
           # Pathname to block device file
           path  = "/dev/loop0"
           # Permission bits expressed as octal integer
           mode  = 0640
           # Device file major number for loopback block device
           major = 7
           # Device file minor number for first loopback block device
           minor = 0
           # Owner UID (root)
           user  = 0
           # Group name
           group = "disk"
   }

fs-chrdev
*********

Define a filesystem character device file entry.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-chrdev**> ::= 'type = "chrdev"'
                   |SSEP| <`fs-path-attr`_>
                   |SSEP| <`fs-mode-attr`_>
                   |SSEP| <`fs-major-attr`_>
                   |SSEP| <`fs-minor-attr`_>
                   [|SSEP| <`user-attr`_>]
                   [|SSEP| <`group-attr`_>]

Use fs-path-attr_ to specify the pathname to the character device file to
create.
Use fs-mode-attr_ to specify its |file mode bits|.
Use fs-major-attr_ and fs-minor-attr_ to specify its |fs-major| and |fs-minor|
numbers respectively.
Attributes mentioned above are *mandatory*.

You may specify the character device file owner thanks to user-attr_. This
attribute is optional and *defaults* to the current |effective user| when
unspecified.

You may also specify the character device file group membership thanks to
group-attr_. This attribute is optional and *defaults* to the current |effective
group| when unspecified.

.. rubric:: Example

.. code-block::

   # Define a loopback block device file
   {
           type  = "chrdev"
           # Pathname to character device file
           path  = "/dev/null"
           # Permission bits expressed as octal integer
           mode  = 0666
           # Device file major number identifying null device class
           major = 1
           # Device file minor number for the null device
           minor = 3
           # Owner
           user  = "root"
           # Group name GID (root)
           group = 0
   }

fs-dir
******

Define a filesystem directory entry.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-dir**> ::= 'type = "dir"'
                |SSEP| <`fs-path-attr`_>
                |SSEP| <`fs-mode-attr`_>
                [|SSEP| <`user-attr`_>]
                [|SSEP| <`group-attr`_>]

Use fs-path-attr_ to specify the pathname to the directory to create.
Use fs-mode-attr_ to specify its |file mode bits|.
Attributes mentioned above are *mandatory*.

You may specify the directory owner thanks to user-attr_. This
attribute is optional and *defaults* to the current |effective user| when
unspecified.

You may also specify the directory group membership thanks to group-attr_. This
attribute is optional and *defaults* to the current |effective group| when
unspecified.

.. rubric:: Example

.. code-block::

   # Define a directory
   {
           type  = "dir"
           # Pathname to directory
           path  = "/tmp/mydir"
           # Permission bits expressed as octal integer
           mode  = 0750
           # Owner
           user  = "myapp"
           # Group name
           group = "myapp"
   }

fs-fifo
*******

Define a filesystem |named pipe| entry, otherwise known as filesystem |fifo|.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-fifo**> ::= 'type = "fifo"'
                 |SSEP| <`fs-path-attr`_>
                 |SSEP| <`fs-mode-attr`_>
                 [|SSEP| <`user-attr`_>]
                 [|SSEP| <`group-attr`_>]

Use fs-path-attr_ to specify the pathname to the |fifo| to create.
Use fs-mode-attr_ to specify its |file mode bits|.
Attributes mentioned above are *mandatory*.

You may specify the |fifo| owner thanks to user-attr_. This
attribute is optional and *defaults* to the current |effective user| when
unspecified.

You may also specify the |fifo| group membership thanks to group-attr_. This
attribute is optional and *defaults* to the current |effective group| when
unspecified.

.. rubric:: Example

.. code-block::

   # Define a directory
   {
           type = "fifo"
           # Pathname to directory
           path = "/tmp/mypipe"
           # Permission bits expressed as octal integer
           mode = 0600
   }

fs-file
*******

Make a |host| file visible from within a |jail|.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-file**> ::= 'type = "file"'
                 |SSEP| <`fs-path-attr`_>
                 |SSEP| <`fs-orig-attr`_>
                 [|SSEP| <`fs-file-flags`_>]
                 [|SSEP| <`fs-bind-opts`_>]

The specified file is |bind mount|'ed into the |jail|.

Use fs-orig-attr_ to specify the |pathname| identifying the file onto the
|host|.  Use fs-path-attr_ to specify a |pathname| *relative* to the |jail|'s
root directory that identifies the file within the |jail|.

Attributes mentioned above are *mandatory*.

Use fs-file-flags_ and fs-bind-opts_ to customize the way the file is made
visible from inside the |jail|. These attributes are optional and *defaults* to
none when unspecified.

.. rubric:: Example

.. code-block::

   # Make /bin/busybox visible as /bin/sh from within a jail
   {
           type   = "file",
           # Pathname to host side Busybox
           orig   = "/bin/busybox",
           # Pathname as seen from inside the jail (relative to jail's root)
           path   = "bin/sh",
           # Busybox is bind mount'ed read-only with SUID bit cleared
           flags  = [ "ro", "nosuid" ]
   }

fs-file-flags
*************

Customize common |bind mount| properties when making a |host| file entry visible
from within a |jail|.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-file-flags**>  ::= 'flags = [' <file-flag-list> ']'
   <**file-flag-list**> ::= '"' <**file-flag**> '"' [|LSEP| '"' <**file-flag**> '"']...
   <**file-flag**>      ::= 'mand'
                      | 'nodev'
                      | 'noexec'
                      | 'nosuid'
                      | 'ro'
                      | 'silent'
                      | 'sync'
                      | 'nosymfollow'
                      | 'lazy'
                      | 'noatime'
                      | 'relatime'
                      | 'strictatime'

Setup common *per-mount-point* flags when making a |host| filesystem entry
visible from within a |jail| using fs-file_ statement.

Flags are given as an array of |STRING| and are documented in section `Mount
flags`_.
This attribute is optional and *defaults* to none when unspecified, meaning that
original host side file's filesystem mounting flags apply.

.. rubric:: Example

.. code-block::
   :emphasize-lines: 14,15,16

   # Define a jail
   jail = {
           ...
           # Setup jail's filesystem content
           fsset = (
                   ...
                   { # Make /bin/busybox visible as /bin/sh from within a jail
                           type   = "file",
                           # Pathname to host side Busybox
                           orig   = "/bin/busybox",
                           # Pathname as seen from inside the jail (relative to
                           # jail's root)
                           path   = "bin/sh",
                           # Busybox is bind mount'ed read-only with SUID bit
                           # cleared
                           flags  = [ "ro", "nosuid" ]
                   }
                   ...
           )
   }

fs-major-attr
*************

Specify the major number of a filesystem device node file entry.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-major-attr**> ::= 'major =' <|fs-major|>

Specify the |fs-major| of a device node file specified by a `top-host`_
statement.

This attribute is *mandatory*.

.. rubric:: Example

.. code-block::
   :emphasize-lines: 8,9

   # Define a loopback block device file
   {
           type  = "blkdev",
           # Pathname to block device file
           path  = "/dev/loop0"
           # Permission bits expressed as octal integer
           mode  = 0640
           # Device file major number for loopback block device
           major = 7
           # Device file minor number for first loopback block device
           minor = 0
   }

fs-minor-attr
*************

Specify the minor number of a filesystem device node file entry.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-minor-attr**> ::= 'minor =' <|fs-minor|>

Specify the |fs-minor| of a device node file specified by a `top-host`_
statement.

This attribute is *mandatory*.

.. rubric:: Example

.. code-block::
   :emphasize-lines: 10,11

   # Define a loopback block device file
   {
           type  = "blkdev",
           # Pathname to block device file
           path  = "/dev/loop0"
           # Permission bits expressed as octal integer
           mode  = 0640
           # Device file major number for loopback block device
           major = 7
           # Device file minor number for first loopback block device
           minor = 0
   }

fs-mode-attr
************

Define the |file mode bits| of a filesystem entry .

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-mode-attr**> ::= 'mode =' <|fs-mode|>

|fs-mode| must be specified as a *positive octal integer*, i.e. prefixed with a
leading ``0`` (as octal literals in C).

.. rubric:: Example

.. code-block::

   ...
   mode = 0640
   ...

fs-orig-attr
************

Define the |pathname| of a |bind mount|'ed filesystem entry.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-orig-attr**> ::= 'orig =' <|pathname|>

|pathname| identifies a |host| filesystem entry to make visible from inside a
|jail|. It must be specified as *absolute* to the |host|'s root directory.

This attribute is *mandatory*.

.. rubric:: Example

.. code-block::
   :emphasize-lines: 12,13

   # Define a jail
   jail = {
           ...
           # Setup jail's filesystem content
           fsset = (
                   ...
                   { # Make /lib visible as /lib from within a jail
                           type  = "tree"
                           # Pathname as seen from inside the jail (relative to
                           # jail's root)
                           path  = "lib"
                           # Pathname to host side /lib subtree
                           orig  = "/lib"
                   },
                   ...
           )
   }


fs-path-attr
************

Define a filesystem entry |pathname|.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-path-attr**> ::= 'path = "' <|pathname|> '"'

.. important::

   When used to define a |jail| filesystem entry (thanks to a jail-fsset_
   statement), |pathname| **MUST** be specified as relative to |jail|'s root
   directory, i.e. with no leading ``/``.

.. rubric:: Example

.. code-block::

   ...
   path = "/mypath"
   ...

fs-proc
*******

Define a |procfs(5)| filesystem entry to be mounted from within a |jail|.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-proc**> ::= 'type = "proc"'
                 [|SSEP| <`fs-proc-flags`_>]
                 [|SSEP| <`fs-bind-opts`_>]

Mount a |procfs(5)| filesystem under the :file:`/proc` mount point into the
|jail|.

.. important::

   Enbox_ implicitly creates the :file:`/proc` mount point directory into the
   |jail|.

Use fs-proc-flags_ and fs-bind-opts_ to customize the way the :file:`/proc` is
made visible from inside the |jail|.

The fs-proc-flags_ attribute is *optional*. See fs-proc-flags_ statement for
more informations about default flags.

The fs-bind-opts_ attribute is *optional* and defaults to the |STRING|
``hidepid=invisible,subset=pid`` when unspecified.

.. rubric:: Example

.. code-block::
   :emphasize-lines: 7-9

   # Define a jail
   jail = {
           ...
           # Setup jail's filesystem content
           fsset = (
                   ...
                   { # Mount a procfs under /proc within the jail
                           type  = "proc"
                   },
                   ...
           )
   }
   
fs-proc-flags
*************

Customize mount properties when mounting a |procfs(5)| inside a |jail|.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-proc-flags**>  ::= 'flags = [' <proc-flag-list> ']'
   <**proc-flag-list**> ::= '"' <**proc-flag**> '"' [|LSEP| '"' <**proc-flag**> '"']...
   <**proc-flag**>      ::= 'nodev'
                      | 'noexec'
                      | 'nosuid'
                      | 'ro'
                      | 'silent'
                      | 'lazy'
                      | 'noatime'
                      | 'relatime'
                      | 'strictatime'
                      | 'nodiratime'

Flags are given as an array of |STRING| and are documented in section `Mount
flags`_.
This attribute is optional and *defaults* to the |STRING| array ``[ "nodev",
"nosuid", "nodev", "noexec", "noatime" ]`` when unspecified.


.. rubric:: Example

.. code-block::
   :emphasize-lines: 9

   # Define a jail
   jail = {
           ...
           # Setup jail's filesystem content
           fsset = (
                   ...
                   { # Mount a procfs under /proc within the jail
                           type  = "proc"
                           flags = [ "nodev", "nosuid", "nodev", "noexec" ]
                   },
                   ...
           )
   }

fs-slink
********

Define a filesystem symbolic link entry.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-slink**>        ::= 'type = "slink"'
                         |SSEP| <`fs-path-attr`_>
                         |SSEP| <**fs-slink-target**>
                         [|SSEP| <`user-attr`_>]
                         [|SSEP| <`group-attr`_>]
   <**fs-slink-target**> ::= 'target = "' <|pathname|> '"'


Use fs-path-attr_ to specify the pathname of symbolic the link to create. Use
**fs-slink-target** attribute to specify the target |pathname| the symbolic link
points to.

Attributes mentioned above are *mandatory*.

You may specify the symbolic link owner thanks to user-attr_. This
attribute is optional and *defaults* to the current |effective user| when
unspecified.

You may also specify the symbolic link group membership thanks to group-attr_.
This attribute is optional and *defaults* to the current |effective group| when
unspecified.

.. rubric:: Example

.. code-block::

   # Define a symbolic link
   {
           type   = "slink"
           # Symbolic link pathname
           path   = "/tmp/mylink"
           # Symbolic link target pathname pointing to /tmp/mytarget...
           target = "mytarget"
   }

fs-tree
*******

Make a |host| filesystem (sub)tree visible from within a |jail|.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-tree**> ::= 'type = "tree"'
                 |SSEP| <`fs-path-attr`_>
                 |SSEP| <`fs-orig-attr`_>
                 [|SSEP| <`fs-tree-flags`_>]
                 [|SSEP| <`fs-bind-opts`_>]

The specified (sub)tree is |bind mount|'ed into the |jail|.

Use fs-orig-attr_ to specify the |pathname| identifying the (sub)tree onto the
|host|.  Use fs-path-attr_ to specify a |pathname| *relative* to the |jail|'s
root directory that identifies the (sub)tree mount point directory within the
|jail|.

.. important::

   Enbox_ implicitly creates |jail|'s (sub)tree mount point when needed.

Attributes mentioned above are *mandatory*.

Use fs-tree-flags_ and fs-bind-opts_ to customize the way the (sub)tree is made
visible from inside the |jail|. These attributes are optional and *defaults* to
none when unspecified.

.. rubric:: Example

.. code-block::
   :emphasize-lines: 7-14

   # Define a jail
   jail = {
           ...
           # Setup jail's filesystem content
           fsset = (
                   ...
                   { # Make /lib visible as /lib from within a jail
                           type  = "tree"
                           # Pathname as seen from inside the jail (relative to
                           # jail's root)
                           path  = "lib"
                           # Pathname to host side /lib subtree
                           orig  = "/lib"
                   },
                   ...
           )
   }

fs-tree-flags
*************

Customize common |bind mount| properties when making a |host| (sub)tree entry
visible from within a |jail|.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**fs-tree-flags**>  ::= 'flags = [' <**tree-flag-list**> ']'
   <**tree-flag-list**> ::= '"' <**tree-flag**> '"' [|LSEP| '"' <**tree-flag**> '"']...
   <**tree-flag**>      ::= 'dirsync'
                      | 'mand'
                      | 'nodev'
                      | 'noexec'
                      | 'nosuid'
                      | 'ro'
                      | 'silent'
                      | 'sync'
                      | 'nosymfollow'
                      | 'lazy'
                      | 'noatime'
                      | 'relatime'
                      | 'strictatime'
                      | 'nodiratime'

Setup common *per-mount-point* flags when making a |host| filesystem entry
visible from within a |jail| using fs-tree_ statement.

Flags are given as an array of |STRING| and are documented in section `Mount
flags`_.
This attribute is optional and *defaults* to none when unspecified, meaning that
original host side (sub)tree's filesystem mounting flags apply.

.. rubric:: Example

.. code-block::
   :emphasize-lines: 11,12,13,14

   # Define a jail
   jail = {
           ...
           # Setup jail's filesystem content
           fsset = (
                   ...
                   { # Import /lib host sub-tree into jail
                           type  = "tree"
                           path  = "lib"
                           orig  = "/lib"
                           # Bind mount /lib read-only, with SUID bit cleared,
                           # with no special # devices support and no inode
                           # access time updates.
                           flags = [ "ro", "nodev", "nosuid", "noatime" ]
                   },
                   ...
           )
   }

group-attr
**********

Assign specified group membership to the related parent object.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**group-attr**> ::= 'group =' <**group**>
   <**group**>      ::= <|gid|> | '"' <|groupname|> '"'

Setup group specified by <**group**> statement to permissions of a parent
filesystem object. See sections `jail-fsset`_ and `top-host`_ for more
informations about concerned filesystem object types.

As shown above, <**group**> may be specified as either a |gid| or a |groupname|.

.. rubric:: Example

.. code-block::
   :emphasize-lines: 7,8

   # Define a loopback block device file
   {
           type  = "blkdev"
           # Pathname to block device file
           path  = "/dev/loop0"
           ...
           # Group name
           group = "disk"
        ...
   }

jail-fsset
**********

Specify how to populate the content of a |jail|'s filesystem.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**jail-fsset**> ::= 'fsset = (' <**jail-fsent**> [|LSEP| <**jail-fsent**>]... ')'
   <**jail-fsent**> ::= '{' <`fs-file`_> | <`fs-dir`_> | <`fs-slink`_> | <`fs-tree`_> | <`fs-proc`_> '}'

`jail-fsset`_ is *optional*. If not defined, the |jail|'s root filesystem is
mounted empty at *command* execution time (see the `top-cmd`_ statement).

|jail|'s filesystem entries are created according to a list of <**jail-fsent**>
statements. Entry definitions must be provided in order so that all leading path
components exist at creation time.

Created entries will be available at *command* execution time (see the
`top-cmd`_ statement). Created entries are implicitly destroyed when the |jail|
dies.

.. rubric:: Example

.. code-block::
   :emphasize-lines: 3-20

   jail = {
           ...
           # Populate the jail filesystem
           fsset = (
                   { # Create the "bin" directory
                           type  = "dir"
                           path  = "bin"
                           user  = 0
                           group = 0
                           mode  = 0755
                   },
                   { # Import the "mybin" file from host filesystem into the
                     # jail under the directory created above
                           type  = "file"
                           path  = "bin/mybin"
                           orig  = "/bin/mybin"
                           flags = [ "ro", "nodev", "nosuid", "noatime" ]
                   },
                   ...
           )
   }

ns-attr
*******

Specify an optional list of |namespaces| to make a |jail| a member of.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**ns-attr**> ::= 'namespaces = [' <**ns-list**> ']'
   <**ns-list**> ::= '"' <**ns**> '"' [|LSEP| '"' <**ns**> '"']...
   <**ns**>      ::= 'mount'
               | 'cgroup'
               | 'uts'
               | 'ipc'
               | 'net'

For each type of namespace specified in the <**ns-list**> statement, Enbox_
creates a new namespace of the given type and makes the |jail| a member of it.

|Namespaces| are given as an array of |STRING|. `ns-attr`_ is *optional* and
defaults to the |STRING| array ``[ "mount", "cgroup", "uts", "ipc", "net" ]``
when unspecified.

.. rubric:: Example

.. code-block::
   :emphasize-lines: 4,5

   # Define a jail
   jail = {
           ...
           # Namespaces the jail is a member of
           namespaces = [ "mount", "uts", "ipc", "net" ]
           ...
   }

top-cmd
*******

Specify an optional external program to |execve(2)| with tunable runtime context
settings.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**top-cmd**> ::= 'cmd = {' <`exec-attr`_> [|SSEP| <`umask-attr`_>] [|SSEP| <`caps-attr`_>] [|SSEP| <`cwd-attr`_>] '}'

`top-cmd`_ is *mandatory* if and only if the `top-jail`_ statement has been
specified. Indeed, spawning a jail without running a command from within it
would be useless.

In addition, specifying a `top-cmd`_ *requires* a valid `top-ids`_ statement so
that the command process may switch to the expected |credentials| before
calling |execve(2)|.

Use `exec-attr`_ to specify how to run the command program.
Use `umask-attr`_ to specify the |umask| to run the command process with.
Use `caps-attr`_ to specify the |capabilities| to run the command process with.
Use `cwd-attr`_ to specify the |cwd| to run the command process with.

.. rubric:: Example

.. code-block::

   # Specify a command to run
   cmd = {
           # List of command arguments given to execve(2)
           exec = [ "/sbin/mydaemon", "--opt", "value" ]
           # Command process's file mode creation mask
           umask = 0137
           # Command process will run with these system capabilities(7)
           caps = [ "net_bind_service", "net_raw" ]
           # Command process's current working directory
           cwd = "/var/lib/mydaemon"
   }
   
top-host
********

Define a list of entries to create onto the host filesystem. This is usefull
when it needs to be dynamically populated at runtime prior to running a command
specified by `top-cmd`_.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**top-host**>   ::= 'host = (' <**host-fsent**> [|LSEP| <**host-fsent**>]... ')'
   <**host-fsent**> ::= '{' <`fs-dir`_> | <`fs-slink`_> | <`fs-chrdev`_> | <`fs-blkdev`_> | <`fs-fifo`_> '}'

If not existing, defined entries will be created. Otherwise, existing entry will
be modified according to specified attributes where possible.
Entry definitions must be provided in order so that all leading path components
exist at creation time.

Created entries may be further *imported* into the jail via the `top-jail`_
statement. They will will be available at *command* execution time (see the
`top-cmd`_ statement).

Note that Enbox_ does not handle the removal of created entries. It is delegated
to system administration tasks.

.. rubric:: Example

.. code-block::

   # Populate the host filesystem
   host = (
           { # Create a /tmp/mydir directory entry.
                   path = "/tmp/mydir"
                   type = "dir"
                   mode = 0755
           },
           { # Create a /tmp/mydir/fifo named pipe entry
                   path = "/tmp/mydir/fifo"
                   type = "fifo"
                   mode = 0644
           }
   )

top-ids
*******

Define system user and groups used to :

* spawn a jail via the `top-jail`_ statement ;
* run a command via the `top-cmd`_ statement.

This setting is not required in the context of a single `top-host`_ statement
configuration.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**top-ids**> ::= 'ids = {' <`user-attr`_> [|SSEP| <`drop-supp-attr`_>] '}'

Use `user-attr`_ to specify the system user to load |credentials| for.

Setup `drop-supp-attr`_ to specify how to load |supplementary groups| the
user specified by `user-attr`_ is a member of.

Note that group access list will always contain the user's primary group.

.. rubric:: Example

.. code-block::

   # Load system user and groups
   ids = {
           # System user and its (implicit) related primary group
           user = "myuser"
           # Do drop supplementary groups myuser is a member of.
           drop_supp = true
   }

top-jail
********

Specify an optional jail to spawn with tunable settings.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**top-jail**>   ::= 'jail = {' [<**jail-attr**> [|SSEP| <**jail-attr**>]... '}'
   <**jail-attr**>  ::= <`ns-attr`_> | <`fs-path-attr`_> | <`jail-fsset`_>

`top-jail`_ is *optional*. If not defined, no jail will be spawned before
running a command specified by a `top-cmd`_ statement.

Specifying a `top-jail`_ *requires* a valid `top-ids`_ statement so that the
jail may be spawend accordingly at runtime.
Specifying a `top-jail`_ also *requires* a valid `top-cmd`_ statement so that
a *command* may be run from inside the jail.

Use `ns-attr`_ to specify which |namespaces| to make the |jail| a member of.
Use `fs-path-attr`_ to specify the |pathname| to the |jail|'s filesystem root
directory.
Use <`jail-fsset`_> to instruct Enbox_ how to populate the |jail|'s filesystem
content.

.. rubric:: Example

.. code-block::

   jail = {
           # Namespaces the jail is a member of
           namespaces = [ "mount", "cgroup", "uts", "ipc", "net" ]
           # Pathname to jail's filesystem root directory
           path       = "/tmp/jail"
           # Populate the jail filesystem
           fsset      = (
                   ...
           )
   }

umask-attr
**********

Within the context of a `top-cmd`_ statement, specify the |umask| to run
the command process with.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**umask-attr**> ::= 'umask =' <|fs-mode|>

This attribute is optional and *defaults* to ``0077`` when unspecified.

.. rubric:: Example

.. code-block::

   # Load system user and groups
   cmd = {
           ...
           umask = 0022
   }

user-attr
*********

Assign specified user to the related parent object.

.. rubric:: Syntax

.. parsed-literal::
   :class: highlight

   <**user-attr**> ::= 'user =' <**user**>
   <**user**>      ::= <|uid|> | '"' <|username|> '"'

Within the context of a parent filesystem object, the `user-attr`_ statement
sets up owner permission bits of the related object.  See sections `jail-fsset`_
and `top-host`_ for more informations about concerned filesystem object types.

Within the context of a `top-ids`_ statement, `user-attr`_ specifies the user to
load |credentials| for.

.. rubric:: Example

.. code-block::
   :emphasize-lines: 7,8

   # Define a loopback block device file
   {
           type  = "blkdev"
           # Pathname to block device file
           path  = "/dev/loop0"
           ...
           # Owner
           user = "root"
           ...
   }

Mount flags
***********

Mount flags for use with `fs-file-flags`_ and `fs-tree-flags`_ statements are
shown in the table below. See |mount(2)| for further
informations.

.. list-table::
   :header-rows: 1
   :stub-columns: 1

   * - Flag
     - |mount(2)| flag
     - Description
   * - dirsync
     - ``MS_DIRSYNC``
     - enable synchronous directory updates
   * - mand
     - ``MS_MANDLOCK``
     - enable mandatory locking
   * - nodev
     - ``MS_NODEV``
     - disable access to device special files
   * - noexec
     - ``MS_NOEXEC``
     - disallow program execution
   * - nosuid
     - ``MS_NOSUID``
     - do not honor SUID / SGID bits or file capabilites when executing programs
   * - ro
     - ``MS_RDONLY``
     - read-only
   * - silent
     - ``MS_SILENT``
     - suppress kernel warning messages for this mount
   * - sync
     - ``MS_SYNCHRONOUS``
     - writes synchronously
   * - nosymfollow
     - ``MS_NOSYMFOLLOW``
     - do not follow symbolic links
   * - lazy
     - ``MS_LAZYTIME``
     - reduce on-disk updates of inode timestamps
   * - noatime
     - ``MS_NOATIME``
     - do not update access times
   * - relatime
     - ``MS_RELATIME``
     - reduce updates of inode last access time
   * - strictatime
     - ``MS_STRICTATIME``
     - always update the last access time
   * - nodiratime
     - ``MS_NODIRATIME``
     - disable directory inode access time updates

Use cases
---------

.. todo::

   Document typical configuration use cases
