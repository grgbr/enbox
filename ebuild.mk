################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Enbox.
# Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

config-in := Config.in
config-h  := enbox/config.h

HEADERDIR := $(CURDIR)/include
headers    = enbox/enbox.h

subdirs   := src

define libenbox_pkgconf_tmpl
prefix=$(PREFIX)
exec_prefix=$${prefix}
libdir=$${exec_prefix}/lib
includedir=$${prefix}/include

Name: libenbox
Description: Embedded sandboxing library
Version: $(VERSION)
Requires.private: libelog libstroll libutils libconfig
Cflags: -I$${includedir}
Libs: -L$${libdir} -Wl,--push-state,--as-needed -lenbox -Wl,--pop-state
endef

pkgconfigs       := libenbox.pc
libenbox.pc-tmpl := libenbox_pkgconf_tmpl

################################################################################
# Source code tags generation
################################################################################

tagfiles := $(shell find $(CURDIR) -type f)

################################################################################
# Documentation generation
################################################################################

doxyconf  := $(CURDIR)/sphinx/Doxyfile
doxyenv   := SRCDIR="$(HEADERDIR) $(SRCDIR)" \
             INCDIR="$(patsubst -I%,%,$(filter -I%,$(common-cflags))) \
                     $(BUILDDIR)" \
             VERSION="$(VERSION)"

sphinxsrc := $(CURDIR)/sphinx
sphinxenv := \
	VERSION="$(VERSION)" \
	$(if $(strip $(EBUILDDOC_TARGET_PATH)), \
	     EBUILDDOC_TARGET_PATH="$(strip $(EBUILDDOC_TARGET_PATH))") \
	$(if $(strip $(EBUILDDOC_INVENTORY_PATH)), \
	     EBUILDDOC_INVENTORY_PATH="$(strip $(EBUILDDOC_INVENTORY_PATH))")

# ex: filetype=make :
