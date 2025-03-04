.. SPDX-License-Identifier: GPL-3.0-only
   
   This file is part of Enbox.
   Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>

.. include:: /_cdefs.rst

.. |user guide| replace:: Enbox_\’s :doc:`User guide </main>`
.. |API guide|  replace:: Enbox_\’s :doc:`API guide </api>`

.. program:: enbox

********
enbox(1)
********

Name
====

enbox - Enbox sanbox tool

Synopsis
========

.. parsed-literal::

   :program:`enbox` [options] show_ [<:option:`CONFIG`>]
   :program:`enbox` [options] run_ [<:option:`CONFIG`>]

   *options*    := :option:`--log-tag`\=<:option:`TAG`>
               | :option:`--stdlog-level`\=<:option:`SEVERITY`>
               | :option:`--syslog-level`\=<:option:`SEVERITY`>
               | :option:`--syslog-facility`\=<:option:`FACILITY`>
               | :option:`--mqlog-level`\=<:option:`SEVERITY`>
               | :option:`--mqlog-facility`\=<:option:`FACILITY`>
               | :option:`--mqlog-name`\=<:option:`NAME`>
               | :option:`-h` | :option:`--help`

Description
===========

:program:`enbox` is a tool that allows to load and apply an Enbox_
configuration.

.. _show:

When the ``show`` argument is given, it displays settings loaded from the
configuration file given as :option:`CONFIG` argument.

.. _run:

When the ``run`` argument is given, it loads then runs the program found into
the configuration file given as :option:`CONFIG` argument.

.. _help:

Finally, the :option:`-h` and :option:`--help` options argument displays a help
message.

Arguments
=========

.. option:: CONFIG

   Pathname to an Enbox_ configuration_ file.

.. option:: FACILITY

   Specify the |syslog(3)| facility used to log diagnostic messages. These are:

   * ``dflt``, the compiled-in default facility (see build time configuration
     option :c:macro:`CONFIG_ENBOX_TOOL_LOG_FACILITY` of |API guide|).
   * ``auth``
   * ``authpriv``
   * ``cron``
   * ``daemon``
   * ``ftp``
   * ``lpr``
   * ``mail``
   * ``news``
   * ``syslog``
   * ``user``
   * ``local0``
   * ``local1``
   * ``local2``
   * ``local3``
   * ``local4``
   * ``local5``
   * ``local6``
   * ``local7``

.. option:: NAME

   Name of POSIX message queue used log diagnostic messages including the
   leading ``/`` character. See |mq_overview(7)| for detailed informations about
   naming scheme.
   Defaults to the compiled-in default POSIX message queue name (see build time
   configuration option :c:macro:`CONFIG_ENBOX_TOOL_MQLOG_NAME` of |API guide|).


.. option:: SEVERITY

   Determine the |syslog(3)| level above which diagnostic messages are not
   output. Severity levels are:

   * ``none`` disables the output of messages completely
   * ``dflt`` disables the output of messages with level higher than the
     compiled-in default severity (see build time configuration option
     :c:macro:`CONFIG_ENBOX_TOOL_LOG_SEVERITY` of |API guide|).
   * ``emerg``
   * ``alert``
   * ``crit``
   * ``err``
   * ``warn``
   * ``notice``
   * ``info``

.. option:: TAG

   A simple label prefixing diagnostic messages. This may be used by the
   |syslog(3)| subsystem to identify message sources, i.e., the program that
   generated a particular message.

Options
=======

.. option:: --log-tag=<TAG>

   Use :option:`TAG` to output diagnostic messages. Defaults to ``enbox``.

.. option:: --stdlog-level=<SEVERITY>

   Setup console log verbosity level to :option:`SEVERITY`.
   When unspecified, defaults to ``dflt``.
   Use ``none`` to completely disable output of diagnostic messages onto the
   console.

.. option:: --syslog-level=<SEVERITY>

   Setup verbosity level to :option:`SEVERITY` for diagnostic messages output to
   the |syslog(3)| subsystem.
   When unspecified, defaults to ``none``.
   Use ``none`` to completely disable output of messages to |syslog(3)|.

.. option:: --syslog-facility=<FACILITY>

   Setup facility to :option:`FACILITY` for messages output to the |syslog(3)|
   subsystem.
   Defaults to the compiled-in default facility (see build time configuration
   option :c:macro:`CONFIG_ENBOX_TOOL_LOG_FACILITY` of |API guide|).

.. option:: --mqlog-level=<SEVERITY>

   Setup verbosity level to :option:`SEVERITY` for diagnostic messages output to
   POSIX message queue through eLog_. This may be useful when an eLogd_ daemon
   locally polls messages from a POSIX message queue to store them onto
   persistent storage.
   When unspecified, defaults to ``none``.
   Use ``none`` to completely disable output of messages to a POSIX message
   queue.

.. option:: --mqlog-facility=<FACILITY>

   Setup facility to :option:`FACILITY` for messages output to eLog_ / eLogd_
   POSIX message queue.
   Defaults to the compiled-in default facility (see build time configuration
   option :c:macro:`CONFIG_ENBOX_TOOL_LOG_FACILITY` of |API guide|).

.. option:: --mqlog-name=<NAME>

   Setup name of POSIX message queue to :option:`NAME` used to log diagnostic
   messages to.
   Defaults to the compiled-in default POSIX message queue name (see build time
   configuration option :c:macro:`CONFIG_ENBOX_TOOL_MQLOG_NAME` of |API guide|).

.. option:: -h, --help

   Output a help message.

Configuration
=============

:option:`CONFIG` configuration file given in argument MUST comply with the
syntax described by section «|Configuration|» of |User guide|.

Note that files included from the :option:`CONFIG` configuration file MUST be
located into the directory setup at Enbox_ build time thanks to the build
configuration option :c:macro:`CONFIG_ENBOX_INCLUDE_DIR` documented into the
|API guide|.

In addition, the :command:`enbox` tool REQUIRES that a «|cmd|» statement be
specified within the :option:`CONFIG` configuration file.
Configuration will be rejected at loading time otherwise.

See also
========

|syslog(3)|
|mq_overview(7)|

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
