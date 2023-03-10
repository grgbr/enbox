.. include:: _cdefs.rst

.. |Build|     replace:: :ref:`Build <sect-build>`
.. |Install|   replace:: :ref:`Install <sect-install>`
.. |DEFCONFIG| replace:: :ref:`DEFCONFIG <var-defconfig>`
.. |INSTALL|   replace:: :ref:`INSTALL <var-install>`

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
* |sphinx|
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

   ==Targets==

   ::Configuration::
     menuconfig    -- configure build using a NCurses menu-driven interface
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

   EBUILDDIR       -- ebuild directory
                      [/usr/local/share/ebuild]
   DEFCONFIG       -- default build configuration file
                      []
   PREFIX          -- prefix prepended to install variable default values
                      [/usr]
   DESTDIR         -- top-level staged / root install directory
                      []
   BUILDDIR        -- build directory
                      [/home/worker/build/enbox]
   CROSS_COMPILE   -- cross complile tool prefix
                      [arm-linux-gnueabihf-]
   EXTRA_CFLAGS    -- additional flags passed to $(CC) at compile time
                      [-mcpu=cortex-a9 -O2 -flto=auto -I/home/staging/usr/include]
   EXTRA_LDFLAGS   -- additional flags passed to $(LD) at link time
                      [-mcpu=cortex-a9 -O2 -flto=auto -L/home/staging/usr/lib -Wl,-rpath-link,/home/staging/usr/lib]

   Use `help-full' target for further details.

Also note that a more detailed help message is available:

.. code-block:: console

   $ make help-full

Workflow
========

As mentioned earlier, Enbox's build logic is based on ebuild_, a |GNU make|
based build system. To build and install Enbox, the typical workflow is:

#. Configure_ the construction logic
#. |Build| programs, libraries, documentation, etc.
#. |Install| components, copying files previously built to
   system-wide directories

The 3 phases mentioned above are subject to customization thanks to multiple
:command:`make` variable settings that may be passed on the command line.  You
are encouraged to adjust values according to your specific needs. Most of the
time, setting BUILDDIR_, PREFIX_ and CROSS_COMPILE_ is sufficient. Refer to the
following sections for further informations.

After a successful |Install| phase, final constructed objects are located under
the directory pointed to by ``$(DESTDIR)$(PREFIX)`` where DESTDIR_ and PREFIX_
are 2 :command:`make` variables the user may specify on the command line to
customize the final install location.

To begin with, configure_ the build process according to the following section.

Configure
---------

To apply Enbox's **default build configuration**, run the following command from
the top-level Enbox's source tree:

.. code-block:: console

   $ make defconfig

You may specify an alternate default build configuration file by giving
:command:`make` a |DEFCONFIG| variable which value points to an arbitrary file
path:

.. code-block:: console

   $ make defconfig DEFCONFIG=$HOME/build/config/enbox.defconfig

This alternate default build configuration file may be generated from current
configuration into the :file:`defconfig` file located under directory pointed to
by the BUILDDIR_ variable:

.. code-block:: console

   $ make saveconfig BUILDDIR=$HOME/build/enbox
     KSAVE   /home/worker/build/enbox/defconfig

Optionally, you may **tweak build options** interactively:

.. code-block:: console

   $ make menuconfig BUILDDIR=$HOME/build/enbox

The :ref:`menuconfig target <menuconfig>` runs a menu-driven user interface
allowing you to configure build options. You may run alternate user interfaces
using the following :command:`make` targets :

* xconfig_ for a QT menu-driven interface,
* and gconfig_ for GTK menu-driven interface.

The default build directory location is overwritten by giving :command:`make`
the BUILDDIR_ variable which value points to an arbitrary pathname. Intermediate
objects are built under the passed directory to prevent from polluting Enbox's
source tree as in the following example:

.. code-block:: console

   $ make defconfig BUILDDIR=$HOME/build/enbox
   
You may refine the configuration logic by giving :command:`make` additional
variables.  *You are encouraged to adjust values according to your specific
needs*. Section Variables_ describes the following variables which are available
for configuration customization purpose:

* EBUILDDIR_,
* |DEFCONFIG|,
* BUILDDIR_,
* KCONF_, KGCONF_, KMCONF_, KXCONF_,
* in addition to variables listed in the Tools_ section.

You may also customize tools used at configuration time. Refer to section Tools_
for more informations.

You can now proceed to the |Build| phase.

.. _sect-build:

Build
-----

To build / compile / link programs, libraries, etc., run the :command:`make`
command like so:

.. code-block:: console

   $ make build

To store intermediate objects under an alternate location, give :command:`make`
the BUILDDIR_ variable like so:

.. code-block:: console

   $ make build BUILDDIR=$HOME/build/enbox

If not completed, the ``build`` target performs the configuration phase
implicitly using default configuration settings.

In addition, you may specify the PREFIX_ variable to change the default final
install location:

.. code-block:: console

   $ make build BUILDDIR=$HOME/build/enbox PREFIX=/
   
You may refine the build logic by giving :command:`make` additional variables.
*You are encouraged to adjust values according to your specific needs*. Section
Reference_ describes the following variables which are available for build
customization purpose:

* EBUILDDIR_, |DEFCONFIG|, KCONF_,
* BUILDDIR_,
* PREFIX_, SYSCONFDIR_, BINDIR_, SBINDIR_, LIBDIR_, LIBEXECDIR_, LOCALSTATEDIR_,
  RUNSTATEDIR_, INCLUDEDIR_, PKGCONFIGDIR_, DATADIR_, DOCDIR_, INFODIR_,
  MANDIR_,
* CROSS_COMPILE_, AR_, CC_, LD_, PKG_CONFIG_, EXTRA_CFLAGS_, EXTRA_LDFLAGS_,
* in addition to variables listed in the Tools_ section.

You may also customize tools used at build time. Refer to section Tools_ for
more informations.

You can now proceed to the |Install| phase.

.. _sect-install:

Install
-------

To install programs, libraries, etc., run the :command:`make` command like so:

.. code-block:: console

   $ make install
   
To store intermediate objects under an alternate location, give :command:`make`
the BUILDDIR_ variable like so:

.. code-block:: console

   $ make install BUILDDIR=$HOME/build/enbox

If not completed, the ``install`` target performs the |Build| phase implicitly.
Files are installed under directory pointed to by the PREFIX_ :command:`make`
variable which defaults to :file:`/usr/local`.

You may specify the PREFIX_ variable to change the default final install
location:

.. code-block:: console

   $ make install BUILDDIR=$HOME/build/enbox PREFIX=/

You may refine the install logic by giving :command:`make` additional variables.
You are encouraged to adjust values according to your specific needs. Section
Reference_ describes the following variables which are available for install
customization purpose:

* EBUILDDIR_, |DEFCONFIG|, KCONF_,
* BUILDDIR_,
* PREFIX_, SYSCONFDIR_, BINDIR_, SBINDIR_, LIBDIR_, LIBEXECDIR_, LOCALSTATEDIR_,
  RUNSTATEDIR_, INCLUDEDIR_, PKGCONFIGDIR_, DATADIR_, DOCDIR_, INFODIR_,
  MANDIR_,
* CROSS_COMPILE_, STRIP_,
* in addition to variables listed in the Tools_ section.

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

   $ make install DESTDIR=$HOME/staging

If usual installation step would normally install :file:`$(BINDIR)/foo` and
:file:`$(LIBDIR)/libfoo.a`, then an installation invoked as in the example above
would install :file:`$(HOME)/staging/$(BINDIR)/foo` and
:file:`$(HOME)/staging/$(LIBDIR)/libfoo.a` instead.

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

Cleanup
-------

3 additional :command:`make` targets are available to cleanup generated objects.

The :ref:`clean target <clean>` remove built objects from the BUILDDIR_
directory without cleaning up installed objects.
In other words, this performs the inverse operation of |Build| target:

.. code-block:: console

   $ make clean BUILDDIR=$HOME/build/enbox

The :ref:`distclean target <distclean>` runs :ref:`clean target <clean>` then
removes build configuration objects from the BUILDDIR_ directory.
In other words, this removes every intermediate objects, i.e., all generated
objects that have not been installed:

.. code-block:: console

   $ make distclean BUILDDIR=$HOME/build/enbox

Finally, the :ref:`uninstall target <uninstall>` removes installed objects from
the $(DESTDIR_)$(PREFIX_) directory.
In other words, this performs the inverse operation of |Install| target:

.. code-block:: console

   $ make uninstall PREFIX= DESTDIR=$HOME/staging

Tools
-----

You may customize tools used during construction phases by giving
:command:`make` additional variables like so:

.. code-block:: console

   $ make build CROSS_COMPILE='armv7-linaro-linux-gnueabihf-'

Section Variables_ describes the following variables which are available for
tool customization purpose:

* AR_,
* CROSS_COMPILE_,
* CC_,
* DOXY_,
* ECHOE_,
* |INSTALL|,
* INSTALL_INFO_,
* KCONF_,
* KMCONF_,
* KXCONF_,
* KGCONF_,
* LATEXMK_,
* MAKEINFO_,
* LD_,
* LN_,
* PKG_CONFIG_,
* PYTHON_,
* RM_,
* RSYNC_,
* SPHINXBUILD_,
* STRIP_.

Reference
=========

Targets
-------

This section describes all :command:`make` targets that may be given on the
command line to run a particular construction phase.

.. _target-build:

build
*****

Compile / link objects and optionally, build documentation objects. Built
objects are stored under BUILDDIR_ directory.

If not completed, the build target performs the configuration phase implicitly
using default configuration settings.

Refer to section |Build| for a list of variables affecting this target
behavior.

clean
*****

Remove built objects and documentation from the BUILDDIR_ directory.

Refer to section |Build| for a list of variables affecting this target
behavior.

clean-doc
*********

Remove built documentation from the BUILDDIR_ directory.

Refer to section |Build| for a list of variables affecting this target
behavior.

.. _target-defconfig:

defconfig
*********

Configure build using default settings. Created configuration objects are stored
under the BUILDDIR_ directory.

Refer to section Configure_ for a list of variables affecting this target
behavior.

distclean
*********

Run :ref:`clean target <clean>` then remove build configuration objects created
by the build configuration targets from the BUILDDIR_ directory.

Refer to section Configure_ for a list of configuration targets variables
affecting this target behavior.

doc
***

Build documentation under BUILDDIR_ directory.

Refer to section |Build| for a list of variables affecting this target
behavior.

gconfig
*******

Edit build configuration using an interactive |GTK| menu-driven interface. 

An arbitrary file containing default options may be specified using |DEFCONFIG|
variable.
These default options are applied when no previous configuration target has been
run.

Refer to section Configure_ for a list of variables affecting this target
behavior.

help
****

Show a brief help message.

help-full
*********

Show a detailed help message.

.. _target-install:

install
*******

Install objects and optionally documentation constructed at :ref:`building
<sect-build>` time. Objects are basically installed under PREFIX_ directory.

If not completed, the install target performs the build phase implicitly using
default configuration settings.

Refer to section |Install| for a list of variables affecting this target
behavior.

In addition, when following a `Staged install`_ workflow, you may alter final
installation directory thanks to the DESTDIR_ variable so that final objects are
deployed under :file:`$(DESTDIR)$(PREFIX)` instead.

install-doc
***********

Install documentation built thanks to :ref:`build target <target-build>` or
:ref:`doc target <doc>` under PREFIX_ directory.

Refer to section |Install| for a list of variables affecting this target
behavior.

In addition, when following a `Staged install`_ workflow, you may alter final
installation directory thanks to the DESTDIR_ variable so that final objects are
deployed under :file:`$(DESTDIR)$(PREFIX)` instead.

install-strip
*************

Run :ref:`install target <target-install>` and discard symbols from installed
objects.

menuconfig
**********

Edit build configuration using an interactive |NCurses| menu-driven interface. 

An arbitrary file containing default options may be specified using |DEFCONFIG|
variable.
These default options are applied when no previous configuration target has been
run.

Refer to section Configure_ for a list of variables affecting this target
behavior.

saveconfig
**********

Save current build configuration into :file:`$(BUILDDIR)/defconfig` default
settings file that can be loaded using a subsequent :ref:`defconfig target
<target-defconfig>` run.

Refer to section Configure_ for a list of variables affecting this target
behavior.

uninstall
*********

Remove installed objects and documentation from the PREFIX_ directory.

In addition, when following a `Staged install`_ workflow, you may alter final
installation directory thanks to the DESTDIR_ variable so that final objects are
removed from the :file:`$(DESTDIR)$(PREFIX)` directory instead.

Refer to sections |Install| and Cleanup_ for a list of variables affecting this
target behavior.

uninstall-doc
*************

Remove installed documentation from the PREFIX_ directory.

In addition, when following a `Staged install`_ workflow, you may alter final
installation directory thanks to the DESTDIR_ variable so that final objects are
removed from the :file:`$(DESTDIR)$(PREFIX)` directory instead.

Refer to sections |Install| and Cleanup_ for a list of variables affecting this
target behavior.

xconfig
*******

Edit build configuration using an interactive |QT| menu-driven interface. 

An arbitrary file containing default options may be specified using |DEFCONFIG|
variable.
These default options are applied when no previous configuration target has been
run.

Refer to section Configure_ for a list of variables affecting this target
behavior.

Variables
---------

This section describes all :command:`make` variables that may be given on the
command line to customize the construction logic.

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

.. _var-defconfig:

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

Top-level staged / root install directory

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

DOXY
****

|doxygen| documentation generation tool

:Default: ``doxygen``
:Mutable: yes

Tool used to generate source code documentation.
See |doxygen(1)|.
 
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

Additional flags given to $(CC_) at compile time.

EXTRA_LDFLAGS
*************

Flags passed to LD linker

:Default: ``-O2``
:Mutable: yes

Additional flags given to $(LD_) at link time.

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

.. _var-install:

INSTALL
*******

Install tool

:Default: ``install``
:Mutable: yes

Tool used to copy filesytem entries and set their attributes.
See |install(1)|.

 
INSTALL_INFO
************

|info_files| page installer tool

:Default: ``install-info``
:Mutable: yes

Tool used to install |texinfo(5)| documentation system |info(5)| pages generated
using |makeinfo(1)| tool.
See also |install-info(1)|.

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

KConfig |GTK| menu based tool

:Default: ``kconfig-gconf``
:Mutable: yes

Tool used to configure the build logic thanks to a |GTK| menu driven user
interface.
See |kconfig|.

KMCONF
******

KConfig |NCurses| menu based tool

:Default: ``kconfig-mconf``
:Mutable: yes

Tool used to configure the build logic thanks to a text menu driven user
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

LATEXMK
*******

|latex| documentation builder tool

:Default: ``latexmk``
:Mutable: yes

Tool used to automate the process of building |latex| documents.
See also |latexmk(1)|.

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

MAKEINFO
********

|info_files| documentation conversion tool

:Default: ``makeinfo``
:Mutable: yes

Tool used to generate |info(5)| pages for the |texinfo(5)| documentation system.
See also |install-info(1)|.
 
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

PYTHON
******

The |python| interpreter version 3.x

:Default: ``python3``
:Mutable: yes

|python| interpreter required by the |sphinx| documentation system.
See |python3(1)| and SPHINXBUILD_.

RM
**

Filesystem entry removal tool

:Default: ``rm -f``
:Mutable: yes

Tool used to delete filesystem entries.
See |rm(1)|.

RSYNC
*****

|rsync| filesystem synchronization tool

:Default: ``rsync``
:Mutable: yes

Tool used to copy / synchronize filesystem hierarchies.
See |rsync(1)|.

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

SPHINXBUILD
***********

|sphinx| documentation generation tool

:Default: ``sphinx-build``
:Mutable: yes

Tool used to generate documentation from a |rest| file hierarchy.
|sphinx-build(1)| may output documentation to multiple format, i.e.
|info_files|, |latex|, *PDF* and *HTML*.
See also PYTHON_, MAKEINFO_, LATEXMK_ and DOXY_.

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

Give :command:`make` an EBUILDDIR_ variable pointing to the top-level ebuild_
read-only data directory like so:

.. code-block:: console
   
   $ make help EBUILDDIR=/usr/local/share/ebuild
