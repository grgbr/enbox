Overview
========

This guide mainly focuses upon the construction process required to install
Enbox.

Prerequisites
=============

The following packages are required to build Enbox:

* a C compiler such as gcc_
* ebuild_
* |GNU make|
* pkg-config_
* kconfig-frontends_
* elog_
* utils_

At runtime, the following packages must be installed:

* elog_
* utils_

Optionally, you may need the following packages to build the documentation:

* doxygen_
* sphinx_
* sphinx_rtd_theme_
* breathe_

.. todo::

   Document sphinx extensions needed to build documentation

Getting help
============

From Enbox source tree root, enter:

.. code-block:: console

   $ make help

... which should output something like:

.. code-block:: console

   ## enbox build usage ##

   ==Synopsis==

   make <TARGET> [<VARIABLE>[=<VALUE>]]...

   ::Where::
     <TARGET>      -- one of the targets described in `Targets' section below
     <VARIABLE>    -- one of the variables described in the `Variables' section
                      below
     <VALUE>       -- a value to assign to the given <VARIABLE>

   ==Targets==

   ::Configuration::
     menuconfig    -- configure build using a menu-driven interface
     xconfig       -- configure build using a QT menu-driven interface
     gconfig       -- configure build using a GTK menu-driven interface
     defconfig     -- configure build using default settings
     saveconfig    -- save current build configuration as default settings

   ::Documentation::
     doc           -- build documentation
     clean-doc     -- remove built documentation
     install-doc   -- install built documentation
     uninstall-doc -- remove installed documentation

   ::Construction::
     build         -- compile and link objects
     clean         -- remove built objects and documentation
     install       -- install built objects and documentation
     install-strip -- run `install' target and strip installed objects
     uninstall     -- remove installed objects and documentation
     distclean     -- run `clean' target then remove build configuration

   ::Help::
     help          -- this help message
     help-full     -- a full reference help message

   ==Variables==

   EBUILDDIR       -- directory where ebuild logic is located
                      [/usr/local/share/ebuild]
   DEFCONFIG       -- optional file containing default build configuration settings
                      []
   PREFIX          -- prefix prepended to install location variables default value
                      [/usr/local]
   DESTDIR         -- root install hierarchy top-level directory
                      []
   BUILDDIR        -- directory where intermediate built objects are generated
                      [/home/worker/build/enbox]
   CROSS_COMPILE   -- prefix prepended to executables used at compile / link time
                      [/usr/bin/arm-linux-gnueabihf-gcc-]
   EXTRA_CFLAGS    -- additional flags passed to $(CC) at compile time
                      [-mcpu=cortex-a9 -O2 -flto=auto -I/home/worker/staging/usr/include]
   EXTRA_LDFLAGS   -- additional flags passed to $(LD) at link time
                      [-mcpu=cortex-a9 -O2 -flto=auto -L/home/worker/staging/lib -Wl,-rpath-link,/home/worker/staging/lib]

   Use `help-full' target for further details.

Also note that a more detailed help message is available:

.. code-block:: console

   $ make help-full

Workflow
========

As mentioned earlier, Enbox's build logic is based on ebuild_, a |GNU make|
based build system. To build and install Enbox, the typical workflow is:

#. Configure_ the construction logic
#. Build_ programs, libraries, documentation, etc.
#. :ref:`Install <sect-install>` components, copying files previously built to
   system-wide directories

Basically, generated objects are store according to the following rules:

* at build configuration time, intermediate objects are stored under $(BUILDDIR) 
* intermediate built objects are stored under $(BUILDDIR)

The 3 phases mentioned above are subject to multiple customizations. 

.. todo::

   Finish me

Configure
---------

To apply Enbox's **default build configuration**, run the following command from
the top-level Enbox's source tree:

.. code-block:: console

   $ make defconfig

You may specify an alternate default build configuration file by giving *make*
a ``DEFCONFIG`` variable which value points to an arbitrary pathname:

.. code-block:: console

   $ make defconfig DEFCONFIG=/home/worker/config/enbox.defconfig

This alternate default build configuration file may be generated from current
configuration into the :file:`defconfig` file located under directory pointed to
by the ``BUILDDIR`` variable:

.. code-block:: console

   $ make saveconfig
     KSAVE   /home/worker/build/enbox/defconfig

Optionally, you may **tweak build options** interactively:

.. code-block:: console

   $ make menuconfig

The ``menuconfig`` target runs a menu-driven user interface allowing you to
configure build options. You may run alternate user interfaces using the
following *make* targets :

* ``xconfig`` for a QT menu-driven interface,
* and ``gconfig`` for GTK menu-driven interface.

Finally, you may overwrite the default build directory location by giving *make*
a ``BUILDDIR`` variable which value points to an arbitrary pathname.
Intermediate objects are built under the passed directory to prevent from
polluting Enbox's source tree:

.. code-block:: console

   $ make defconfig BUILDDIR=/home/worker/build/enbox

All *make* targets...
.. todo::

   Finish me

You can now proceed to the Build_ phase.

Build
-----

To build / compile / link programs, libraries, etc., run the :command:`make`
command like so:

.. code-block:: console

   $ make build


To build programs, libraries, etc., run:

.. code-block:: console

   $ make build BUILDDIR=/home/worker/build/enbox

If not completed, the ``build`` target performs the configuration phase
implicitly using default configuration settings.


You may overwrite default 
   $ make build PREFIX="" BUILDDIR="" DEFCONFIG=/home/worker/config/enbox.defconfig

.. todo::

   Finish me

You can now proceed to the :ref:`Install <sect-install>`_ phase.

.. _sect-install:

Install
-------

To install programs, libraries, etc., run the :command:`make` command like so:

.. code-block:: console

   $ make install

If not completed, the ``install`` target performs the Build_ phase implicitly.
Files are installed under directory pointed to by the PREFIX_ :command:`make`
variable which defaults to :file:`/usr/local`.

You may refine the install logic by giving :command:`make` additional variables.
You are encouraged to adjust values according to your specific needs. Most of
the time, setting BUILDDIR_, PREFIX_ and CROSS_COMPILE_ is sufficient:

.. code-block:: console

   $ make install PREFIX= DATADIR=/usr/share

Section Reference_ describes the following variables which are available for
install customization purpose:

* PREFIX_,
* SYSCONFDIR_,
* BINDIR_,
* SBINDIR_,
* LIBDIR_,
* LIBEXECDIR_,
* DATADIR_,
* LOCALSTATEDIR_,
* RUNSTATEDIR_,
* INCLUDEDIR_,
* PKGCONFIGDIR_,
* DOCDIR_,
* INFODIR_,
* MANDIR_.

You may also customize tools used at install time. Refer to section Tools_ for
more informations.

Staged install
--------------

DESTDIR_ :command:`make` variable allows support for staged install, i.e. an
install workflow where files are deployed under an alternate top-level root
directory instead of the usual directory pointed to by PREFIX_.

Basically, the DESTDIR_ variable is prepended to each installed target file so
that an install recipe might look something like:

.. code-block:: make

   install:
        $(INSTALL) foo $(DESTDIR)$(BINDIR)/foo
        $(INSTALL) libfoo.a $(DESTDIR)$(LIBDIR)/libfoo.a

The DESTDIR_ variable should be specified by the user on the make command line
as an absolute file name. For example:

.. code-block:: console

   $ make install DESTDIR=/home/worker/root

If usual installation step would normally install :file:`$(BINDIR)/foo` and
:file:`$(LIBDIR)/libfoo.a`, then an installation invoked as in the example above
would install :file:`/home/worker/root/$(BINDIR)/foo` and
:file:`/home/worker/root/$(LIBDIR)/libfoo.a` instead.

Prepending the variable DESTDIR_ to each target in this way provides for staged
installs, where the installed files are not placed directly into their expected
location but are instead copied into a temporary location (DESTDIR). However,
installed files maintain their relative directory structure and any embedded
file names will not be modified.

DESTDIR_ support is commonly used in package creation. It is also helpful to
users who want to understand what a given package will install where, and to
allow users who don’t normally have permissions to install into protected areas
to build and install before gaining those permissions.

Finally, it can be usefull when installing in a cross compile environment where
installation is performed according to a 2 stages process.
An initial stage installs files under a top-level root directory hierarchy
pointed to by the DESTDIR_ variable onto the development host. This step is
generally part of a larger process which constructs the whole final system image
to install onto the target host.
Then, the second stage carries out final system image installation onto the
target host thanks to a specific *installer* runtime that is out of scope of
this document.

Refer to |gnu_install_destdir| for more informations.

Tools
-----

You may customize tools used during construction phases by giving
:command:`make` additional variables like so:

.. code-block:: console

   $ make build CROSS_COMPILE='armv-linaro-linux-gnueabihf-'

Section Reference_ describes the following variables which are available for
tool customization purpose:

* CROSS_COMPILE_,
* CC_,
* AR_,
* LD_,
* STRIP_,
* ECHOE_,
* RM_,
* LN_,
* PKG_CONFIG_,
* INSTALL_,
* KCONF_,
* KMCONF_,
* KXCONF_,
* KGCONF_,
* KNCONF_.

Reference
=========

Variables
---------

AR
**

Object archiver

:Default: ${CROSS_COMPILE_}ar
:Mutable: yes

Tool used to create static libraries, i.e. built objects archives.

See |ar(1)|.

BINDIR
******

Executable programs install directory

:Default: ${PREFIX_}/bin
:Mutable: yes

Pathname to directory where to install executable programs. Note that final
install location is also affected by the DESTDIR_ variable.

See |gnu_vars_for_install_dirs|.

BUILDDIR
********

Build directory

:Default: ${TOPDIR_}/build
:Mutable: yes

Pathname to directory under which intermediate objects are generated. Applies to
all construction phases.

CC
**

C compiler

:Default: ${CROSS_COMPILE_}gcc
:Mutable: yes

Tool used to build C objects.

See |gcc(1)|.

CROSS_COMPILE
*************

Cross compile tool prefix

:Default: empty
:Mutable: yes

Optional prefix prepended to build tools used during construction. The following
variables are affected: AR_, CC_, LD_, STRIP_.

DEFCONFIG
*********

Defaut build configuration file

:Default: empty
:Mutable: yes

Pathname to optional file containing default build configuration settings. This
file may be generated from current configuration as explained into section
configure_.

DATADIR
*******

Read-only architecture-independent data install directory

:Default: ${PREFIX_}/share
:Mutable: yes

Pathname to directory where to install read-only architecture-independent data
files.

See |gnu_vars_for_install_dirs|.

DESTDIR
*******

Top-level root install directory

:Default: empty
:Mutable: yes

*DESTDIR* variable is prepended to each installed target file so that the
installed files are not placed directly into their expected location but are
instead copied into an alternate location, *DESTDIR*.
However, installed files maintain their relative directory structure and any
embedded file names will not be modified.


*DESTDIR* is commonly used in package creation and cross compile environment.
See section `Staged install`_ and |gnu_install_destdir| for more informations.

DOCDIR
******

Documentation install directory

:Default: ${DATADIR_}/doc
:Mutable: yes

Pathname to directory where to install documentation files other than man pages
and info files.

See |gnu_vars_for_install_dirs|.

EBUILDDIR
*********

`Ebuild <ebuild_>`_ directory

:Default: empty
:Mutable: yes

Pathname to directory where ebuild_ logic is located.

ECHOE
*****

Shell escaped string echo'ing tool

:Default: ``/bin/echo -e``
:Mutable: yes

Tool used to print strings to console with shell backslash escapes
interpretation enabled. See |echo(1)|.

EXTRA_CFLAGS
************

Flags passed to C compiler

:Default: ``-O2 -NDEBUG``
:Mutable: yes

Flags given to $(CC_) at compile time.

EXTRA_LDFLAGS
*************

Flags passed to LD linker

:Default: ``-O2``
:Mutable: yes

Flags given to $(LD_) at link time.

INFODIR
*******

|info_files| install directory

:Default: ${DATADIR_}/info
:Mutable: yes

Pathname to directory where to install |info_files|.
See |gnu_vars_for_install_dirs|.

INCLUDEDIR
**********

Header files install directory

:Default: ${PREFIX_}/include
:Mutable: yes

Pathname to directory where to install development header files to be included
by the C ``#include`` preprocessor directive.
See |gnu_vars_for_install_dirs|.

INSTALL
*******

Install tool

:Default: ``install``
:Mutable: yes

Tool used to copy filesytem entries and set their attributes.
See |install(1)|.

KCONF
*****

KConfig line-oriented tool

:Default: ``kconfig-conf``
:Mutable: yes

Tool used to configure the build logic thanks to a line-oriented user interface
(questions - answers).
See |kconfig|.

KGCONF
******

KConfig |GTK| based tool

:Default: ``kconfig-gconf``
:Mutable: yes

Tool used to configure the build logic thanks to a |GTK| menu driven user
interface.
See |kconfig|.

KMCONF
******

KConfig text menu based tool

:Default: ``kconfig-mconf``
:Mutable: yes

Tool used to configure the build logic thanks to a text menu driven user
interface.
See |kconfig|.

KNCONF
******

KConfig |NCurses| menu based tool

:Default: ``kconfig-nconf``
:Mutable: yes

Tool used to configure the build logic thanks to a |NCurses| menu driven user
interface.
See |kconfig|.

KXCONF
******

KConfig |QT| menu based tool

:Default: ``kconfig-qconf``
:Mutable: yes

Tool used to configure the build logic thanks to a |QT| menu driven user
interface.
See |kconfig|.

LD
**

Program linker

:Default: ${CROSS_COMPILE_}gcc
:Mutable: yes

Tool used to link objects.

See |gcc(1)| and |ld(1)|.

LIBDIR
******

Libraries install directory

:Default: ${PREFIX_}/lib
:Mutable: yes

Pathname to directory where to install object files and libraries of object
code.
Note that final install location is also affected by the DESTDIR_ variable.
See |gnu_vars_for_install_dirs|.

LIBEXECDIR
**********

Executable programs install directory

:Default: ${PREFIX_}/libexec
:Mutable: yes

Pathname to directory where to install executable programs to be run by other
programs rather than by users.
Note that final install location is also affected by the DESTDIR_ variable.
See |gnu_vars_for_install_dirs|.

LN
**

Link maker tool

:Default: ``ln -f``
:Mutable: yes

Tool used to make links between filesystem entries.
See |ln(1)|.

LOCALSTATEDIR
*************

Machine specific persistent data files install directory

:Default: ${PREFIX_}/var
:Mutable: yes

Pathname to directory where to install data files which the programs modify
while they run, and that pertain to one specific machine.
Note that final install location is also affected by the DESTDIR_ variable.
See |gnu_vars_for_install_dirs|.

MANDIR
******

Man pages install directory

:Default: ${DATADIR_}/man
:Mutable: yes

Pathname to top-level directory where to install man pages.
See |gnu_vars_for_install_dirs| and |man-pages(7)|.

PREFIX
******

Prefix prepended to install variable default values.

:Default: :file:`/usr/local`
:Mutable: yes

A prefix used in constructing the default values of some of the variables listed
in the Variables_ section.
Note that final install location is also affected by the DESTDIR_ variable.
See |gnu_vars_for_install_dirs|.

PKG_CONFIG
**********

pkg-config_ compile and link helper tool

:Default: ``pkg-config``
:Mutable: yes

Helper tool used to retrieve flags when compiling applications and libraries.
See pkg-config_ and |pkg-config(1)|.

PKGCONFIGDIR
************

pkg-config_ metadata files install directory

:Default: ${LIBDIR_}/pkgconfig
:Mutable: yes

Pathname to directory where to install |pkg-config(1)| metadata files.
See |gnu_vars_for_install_dirs|.

RM
**

Filesystem entry removal tool

:Default: ``rm -f``
:Mutable: yes

Tool used to delete filesystem entries.
See |rm(1)|.

RUNSTATEDIR
***********

Machine specific temporary data files install directory

:Default: ${PREFIX_}/run
:Mutable: yes

Pathname to directory where to install data files which the programs modify
while they run, and that pertain to one specific machine, and which need not
persist longer than the execution of the program.
Note that final install location is also affected by the DESTDIR_ variable.
See |gnu_vars_for_install_dirs|.

SBINDIR
*******

System administration executable programs install directory

:Default: ${PREFIX_}/sbin
:Mutable: yes

Pathname to directory where to install executable programs that are only
generally useful to system administrators. Note that final install location is
also affected by the DESTDIR_ variable.
See |gnu_vars_for_install_dirs|.

STRIP
*****

Object symbols discarding tool.

:Default: ${CROSS_COMPILE_}strip
:Mutable: yes

Tool used to discard symbols from compiled and linked object files.
See |strip(1)|.

SYSCONFDIR
**********

Machine specific read-only configuration install directory

:Default: ${PREFIX_}/etc
:Mutable: yes

Pathname to directory where to install read-only data files that pertain to a
single machine, i.e., files for configuring a host.
Note that final install location is also affected by the DESTDIR_ variable.
See |gnu_vars_for_install_dirs|.

TOPDIR
******

Source tree top-level directory

:Default: not applicable
:Mutable: no

Pathname to source tree top-level directory.

Troubleshooting
===============

In case an error happens such as the one below:

.. code-block:: console

   $ make help
   Makefile:10: *** '/usr/share/ebuild': no valid Ebuild install found !.  Stop.
   
This means Enbox is not able to find the location where ebuild_ is installed. 
This may happen when working with an Enbox source tree that has been retrieved
from version control system, i.e., not extracted from a source distribution
tarball.

Give *make* an ``EBUILDDIR`` variable pointing to the top-level ebuild_
read-only data directory like so:

.. code-block:: console
   
   $ make help EBUILDDIR=/usr/local/share/ebuild

.. include:: _cdefs.rst
