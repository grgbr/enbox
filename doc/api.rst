.. index:: pair: page; Enbox API
.. _doxid-indexpage:

API
===

What follows here provides a thorough description of how to use Enbox's library.



.. _doxid-index_1about-sec:

About
~~~~~

Basically, Enbox library is a C framework meant to instantiate a Linux process from within a «runtime container», providing the ability to control the process accesses to system resources according to a predefined configuration. The container logic implementation is based upon Linux's namespaces. As stated into `namespaces(7) <https://man7.org/linux/man-pages/man7/namespaces.7.html>`__ man page : A namespace wraps a global system resource in an abstraction that makes it appear to the processes within the namespace that they have their own isolated instance of the global resource. Changes to the global resource are visible to other processes that are members of the namespace, but are invisible to other processes.

The library also comes with additional utility functions allowing to manipulate Linux system objects in a limited way. These are :

* `capabilities(7) <https://man7.org/linux/man-pages/man7/capabilities.7.html>`__,

* `namespaces(7) <https://man7.org/linux/man-pages/man7/namespaces.7.html>`__,

* filesystem objects,

* process `credentials(7) <https://man7.org/linux/man-pages/man7/credentials.7.html>`__.





.. _doxid-index_1usage-sec:

Usage
~~~~~

Enbox library API is organized around the following functional areas which you can refer to for further details :

* :ref:`initialization <doxid-group__init>`,

* :ref:`configuration <doxid-group__conf>`,

* :ref:`instantiation <doxid-group__instance>`,

* and :ref:`utilities <doxid-group__utils>`.

The typical sequence of operations involves using the first 3 functional areas mentioned above. Most of the time, you use Enbox library in one of the 2 following ways :

* `run an Enbox configuration from filesystem <#run-from-fs>`__

* or `run an Enbox configuration from pre-defined hard-coded values <#run-from-struct>`__.



.. _doxid-index_1run-from-fs:

Run a configuration from filesystem
-----------------------------------

This mode of operation is meant to apply and execute an Enbox configuration stored into a file. This file must be formatted according to the configuration syntax detailed into the `configuration syntax section <#conf-syntax>`__.

Additional usage details may be found into section :ref:`Configuration <doxid-group__conf>`. This is the most straightforward way to use the Enbox library.





.. _doxid-index_1run-from-struct:

Run a configuration from hard-coded values
------------------------------------------

This mode of operation is meant to apply and execute an Enbox configuration from pre-defined hard-coded values found into multiple binary structures built at compile-time.

Additional usage details may be found into section :ref:`Instantiation <doxid-group__instance>`. This is the most complex way to use the Enbox library.







.. _doxid-index_1conf-syntax:

Configuration syntax
~~~~~~~~~~~~~~~~~~~~

Enbox parses configuration using the `libconfig library <https://hyperrealm.github.io/libconfig>`__. Configuration follows syntax rules described in the `libconfig manual <http://www.hyperrealm.com/libconfig/libconfig_manual.html>`__. Please take a look at the `libconfig manual <http://www.hyperrealm.com/libconfig/libconfig_manual.html>`__ for an explanation of basic types.

COMPLETE ME !!!

Modules
~~~~~~~

.. toctree::
   :hidden:
   :glob:

   api/group_*

Global
~~~~~~

.. toctree::
   :hidden:

   api/global.rst
