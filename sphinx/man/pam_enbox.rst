.. SPDX-License-Identifier: GPL-3.0-only
   
   This file is part of Enbox.
   Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>

.. include:: /_cdefs.rst

.. |user guide| replace:: Enbox_\’s :doc:`User guide </main>`
.. |API guide|  replace:: Enbox_\’s :doc:`API guide </api>`
.. |enbox(1)|   replace:: :doc:`enbox(1) </man/enbox>`

.. program:: pam_enbox.so

************
pam_enbox(8)
************

Name
====

pam_enbox - PAM module for configuring an Enbox_ container

Synopsis
========

.. parsed-literal::

   :program:`pam_enbox.so` [:option:`debug`] [:option:`no_warn`] conf=<:option:`CONFIG`>

Description
===========

The :program:`pam_enbox` PAM_ module sets up a container for a session
according to an Enbox_ configuration defined into the file specified by the
given :option:`CONFIG` argument.
The module may isolate the PAM_ session from the |host| system. For additional
information about available features, refer to the |user guide|.

Arguments
=========

.. option:: CONFIG

   Pathname to an Enbox_ configuration file.

Options
=======

.. option:: debug

   A lot of debug information is logged using |syslog(3)|.

.. option:: no_warn

   Do not give warnings about things, warnings are issued via |syslog(3)|
   otherwise.

Module types provided
=====================

Only the **session** module type is provided. The module must not be called from
multithreaded processes.

Return values
=============

PAM_SUCCESS
    Namespace setup was successful.

PAM_SESSION_ERR
    Unexpected Enbox_ container configuration error occurred.

Examples
========

For the services you need containerisation for (:program:`login` for example),
put the following line in /etc/pam.d/<service> as the last line for session
group::

   session required pam_enbox.so /etc/security/enbox_login.conf

Notes
=====

Note that contrary to the |enbox(1)| tool, the :program:`pam_enbox` PAM_ module
treats the following statements in a specific way when found within the
configuration file passed as the :option:`CONFIG` argument :

* an error occurs when a ``cmd`` statement is specified (see the
  :ref:`top-cmd <sect-main-top_cmd>` section of Enbox_\’s
  :doc:`User guide </main>` ;
* an error occurs when a ``caps`` attribute is specified within a top-level
  ``proc`` statement (see :ref:`caps-attr <sect-main-caps_attr>` and
  :ref:`top-proc <sect-main-top_proc>` sections of Enbox_\’s
  :doc:`User guide </main>`.


See also
========

|pam(8)|
|enbox(1)|

.. only:: man

   .. |DATADIR| replace:: *DATADIR*
   .. |DOCDIR|  replace:: *DOCDIR*

.. only:: not man

   .. |DATADIR| replace:: :external+ebuild:ref:`var-datadir`
   .. |DOCDIR|  replace:: :external+ebuild:ref:`var-docdir`

Enbox_\’s :doc:`User guide </main>` is available locally in HTML format at
|DOCDIR|/enbox/html/user.html, or via :command:`info enbox_user` info page.

Enbox_\’s :doc:`Integration manual </install>` is available locally in HTML
format at |DOCDIR|/enbox/html/install.html, or via :command:`info enbox_install`
info page.

Enbox_\’s :doc:`API guide </api>` is available locally in HTML format at
|DOCDIR|/enbox/html/api.html location or via :command:`info enbox_api` info
page.

In addition, all manuals mentionned above are available locally in PDF format at
|DOCDIR|/enbox/enbox.pdf.

Note that `Latest documentation <https://grgbr.github.io/enbox/>`_ is available
online at https://grgbr.github.io/enbox/.
