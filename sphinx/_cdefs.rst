.. SPDX-License-Identifier: GPL-3.0-only
   
   This file is part of Enbox.
   Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>

..
   Replacement macros to reference libconfig types.
   
.. |BOOL|   replace:: <:ref:`BOOL <libconfig-types>`>
.. |STRING| replace:: <:ref:`STRING <libconfig-types>`>
.. |LSEP|   replace:: <:ref:`LSEP <syntax-sep>`>
.. |SSEP|   replace:: <:ref:`SSEP <syntax-sep>`>


..
   Replacement macros to reference terminology and definitions

.. |credentials|   replace:: :ref:`credentials <sect-main-credentials>`
.. |host|          replace:: :ref:`host <sect-main-host>`
.. |jail|          replace:: :ref:`jail <sect-main-jail>`
.. |namespaces|    replace:: :ref:`namespaces <sect-main-namespaces>`
.. |capabilities|  replace:: :ref:`capabilities <sect-main-capabilities>`
.. |configuration| replace:: :ref:`capabilities <sect-main-configuration>`


..
   Replacement macros to reference glossary entries
   
.. |cwd|                  replace:: :term:`current working directory`
.. |bind mount|           replace:: :term:`bind mount`
.. |gid|                  replace:: :term:`gid`
.. |effective group|      replace:: :term:`effective group`
.. |effective user|       replace:: :term:`effective user`
.. |fifo|                 replace:: :term:`fifo`
.. |fs-major|             replace:: :term:`fs-major`
.. |fs-minor|             replace:: :term:`fs-minor`
.. |fs-mode|              replace:: :term:`fs-mode`
.. |file mode bits|       replace:: :term:`file mode bits`
.. |groupname|            replace:: :term:`groupname`
.. |named pipe|           replace:: :term:`named pipe`
.. |pathname|             replace:: :term:`pathname`
.. |pid|                  replace:: :term:`pid`
.. |pipe|                 replace:: :term:`pipe`
.. |real group|           replace:: :term:`real group`
.. |real user|            replace:: :term:`real user`
.. |supplementary groups| replace:: :term:`supplementary groups`
.. |uid|                  replace:: :term:`uid`
.. |username|             replace:: :term:`username`
.. |umask|                replace:: :term:`umask`


..
   Replacement macros to reference man pages

.. |capabilities(7)|       replace:: :manpage:`capabilities(7)`
.. |chmod(2)|              replace:: :manpage:`chmod(2)`
.. |chroot(8)|             replace:: :manpage:`chroot(8)`
.. |cgroup_namespaces(7)|  replace:: :manpage:`cgroup_namespaces(7)`
.. |credentials(7)|        replace:: :manpage:`credentials(7)`
.. |execve(2)|             replace:: :manpage:`execve(2)`
.. |exit(2)|               replace:: :manpage:`exit(2)`
.. |fifo(7)|               replace:: :manpage:`fifo(7)`
.. |fork(2)|               replace:: :manpage:`fork(2)`
.. |getcwd(3)|             replace:: :manpage:`getcwd(3)`
.. |getgroups(2)|          replace:: :manpage:`getgroups(2)`
.. |getpid(2)|             replace:: :manpage:`getpid(2)`
.. |group(5)|              replace:: :manpage:`group(5)`
.. |initgroups(3)|         replace:: :manpage:`initgroups(3)`
.. |login.defs(5)|         replace:: :manpage:`login.defs(5)`
.. |makedev(3)|            replace:: :manpage:`makedev(3)`
.. |mount_namespaces(7)|   replace:: :manpage:`mount_namespaces(7)`
.. |mount(2)|              replace:: :manpage:`mount(2)`
.. |mount(8)|              replace:: :manpage:`mount(8)`
.. |namespaces(7)|         replace:: :manpage:`namespaces(7)`
.. |network_namespaces(7)| replace:: :manpage:`network_namespaces(7)`
.. |passwd(5)|             replace:: :manpage:`passwd(5)`
.. |pipe(7)|               replace:: :manpage:`pipe(7)`
.. |procfs(5)|             replace:: :manpage:`procfs(5)`
.. |path_resolution(7)|    replace:: :manpage:`path_resolution(7)`
.. |pid_namespaces(7)|     replace:: :manpage:`pid_namespaces(7)`
.. |setresuid(2)|          replace:: :manpage:`setresuid(2)`
.. |umask(2)|              replace:: :manpage:`umask(2)`
.. |user_namespaces(7)|    replace:: :manpage:`user_namespaces(7)`


..
   External hyperlinks definitions

.. _libconfig-bool:      https://hyperrealm.github.io/libconfig/libconfig_manual.html#Boolean-Values
.. _libconfig-string:    https://hyperrealm.github.io/libconfig/libconfig_manual.html#String-Values
.. _libconfig library:   https://hyperrealm.github.io/libconfig
.. _libconfig manual:    http://www.hyperrealm.com/libconfig/libconfig_manual.html
.. _utility conventions: https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html
.. _IEEE Std 1003.1:     https://pubs.opengroup.org/onlinepubs/9699919799/mindex.html
.. _elog:                https://github.com/grgbr/elog/
.. _utils:               https://github.com/grgbr/utils/
.. _breathe:             https://github.com/michaeljones/breathe/
.. _gcc:                 https://gcc.gnu.org/
.. _enbox:               https://github.com/grgbr/enbox/
.. _no_new_privs:        https://docs.kernel.org/userspace-api/no_new_privs.html


..
   External hyperlinks definitions for ebuild related documentation
   
.. |ar(1)|           replace:: :manpage:`ar(1)`
.. |gcc(1)|          replace:: :manpage:`gcc(1)`
.. |echo(1)|         replace:: :manpage:`echo(1)`
.. |install(1)|      replace:: :manpage:`install(1)`
.. |ld(1)|           replace:: :manpage:`ld(1)`
.. |ln(1)|           replace:: :manpage:`ln(1)`
.. |man-pages(7)|    replace:: :manpage:`man-pages(7)`
.. |pkg-config(1)|   replace:: :manpage:`pkg-config(1)`
.. |rm(1)|           replace:: :manpage:`rm(1)`
.. |strip(1)|        replace:: :manpage:`strip(1)`
.. |doxygen(1)|      replace:: :manpage:`doxygen(1)`
.. |texinfo(5)|      replace:: :manpage:`texinfo(5)`
.. |info(5)|         replace:: :manpage:`info(5)`
.. |makeinfo(1)|     replace:: :manpage:`makeinfo(1)`
.. |install-info(1)| replace:: :manpage:`install-info(1)`
.. |latexmk(1)|      replace:: :manpage:`latexmk(1)`
.. |python3(1)|      replace:: :manpage:`python3(1)`
.. |rsync(1)|        replace:: :manpage:`rsync(1)`
.. |sphinx-build(1)| replace:: :manpage:`sphinx-build(1)`

.. _gnu_make:                  https://www.gnu.org/software/make/
.. |GNU Make|                  replace:: `GNU Make <gnu_make_>`_
.. _gnu_vars_for_install_dirs: https://www.gnu.org/prep/standards/html_node/Directory-Variables.html
.. |gnu_vars_for_install_dirs| replace:: `GNU variables for installation Directories <gnu_vars_for_install_dirs_>`_
.. _gnu_install_destdir:       https://www.gnu.org/prep/standards/html_node/DESTDIR.html#DESTDIR
.. |gnu_install_destdir|       replace:: `DESTDIR: support for staged installs <gnu_install_destdir_>`_
.. _texinfo:                   https://www.gnu.org/software/texinfo/
.. |info_files|                replace:: `Info files <texinfo_>`_
.. _kconfig-frontends:         https://salsa.debian.org/philou/kconfig-frontends/
.. |kconfig|                   replace:: `KConfig <kconfig-frontends_>`_
.. _gtk:                       https://www.gtk.org/
.. |GTK|                       replace:: `GTK <gtk_>`_
.. _ncurses:                   https://invisible-island.net/ncurses/
.. |NCurses|                   replace:: `NCurses <ncurses_>`_
.. _qt:                        http://qt-project.org/
.. |QT|                        replace:: `QT <qt_>`_
.. _pkg-config:                https://www.freedesktop.org/wiki/Software/pkg-config/
.. _doxygen:                   https://www.doxygen.nl/
.. |doxygen|                   replace:: `Doxygen <doxygen_>`_
.. _latex:                     https://www.latex-project.org/
.. |latex|                     replace:: `LaTeX <latex_>`_
.. _python:                    https://www.python.org/
.. |python|                    replace:: `Python <python_>`_
.. _sphinx:                    http://sphinx-doc.org/
.. |sphinx|                    replace:: `Sphinx <sphinx_>`_
.. _sphinx_rtd_theme:          https://sphinx-rtd-theme.readthedocs.io/
.. _rsync:                     https://rsync.samba.org/ 
.. |rsync|                     replace:: `Rsync <rsync_>`_
.. _rest:                      https://docutils.sourceforge.io/rst.html
.. |rest|                      replace:: `reStructuredText <rest_>`_
