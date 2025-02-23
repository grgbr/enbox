################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Enbox.
# Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

config-in           := Config.in
config-h            := enbox/config.h

common-cflags       := -Wall -Wextra -Wformat=2 $(EXTRA_CFLAGS)

solibs              := libenbox.so
libenbox.so-objs     = lib.o priv.o conf.o
libenbox.so-cflags   = $(common-cflags) -DPIC -fpic
libenbox.so-ldflags  = $(EXTRA_LDFLAGS) \
                       -shared -Bsymbolic -fpic -Wl,-soname,libenbox.so
libenbox.so-pkgconf := libelog libutils libstroll libconfig

bins                 = $(call kconf_enabled,ENBOX_TOOL,enbox)
enbox-objs           = enbox.o
enbox-cflags         = $(common-cflags)
enbox-ldflags        = $(EXTRA_LDFLAGS) -lenbox
enbox-pkgconf       := libelog libutils
enbox-path          := $(SBINDIR)/enbox

HEADERDIR           := $(CURDIR)/include
headers              = enbox/enbox.h

$(addprefix $(BUILDDIR)/,$(libenbox.so-objs)): $(SRCDIR)/common.h

# Common definitions depend on generated mounting flag definitions.
$(SRCDIR)/common.h: $(BUILDDIR)/mount_flags.h \
                    $(BUILDDIR)/namespaces.h \
                    $(BUILDDIR)/capabilities.h

# Configuration object depends on generated mounting flag descriptor table.
$(BUILDDIR)/conf.o: $(BUILDDIR)/mount_flags.i \
                    $(BUILDDIR)/namespaces.i

$(BUILDDIR)/priv.o: $(BUILDDIR)/capabilities.i

# Generate mounting flags header
$(BUILDDIR)/mount_flags.h: $(SRCDIR)/scripts/gen_flag_descs_header \
                           $(SRCDIR)/mount_flags.in
	@echo "  GEN     $(@)"
	$(Q)$(<) -v macro=ENBOX_MOUNT_FLAGS_LEN $(SRCDIR)/mount_flags.in > $(@)

# Generate mounting flags header
$(BUILDDIR)/namespaces.h: $(SRCDIR)/scripts/gen_flag_descs_header \
                          $(SRCDIR)/namespaces.in
	@echo "  GEN     $(@)"
	$(Q)$(<) -v macro=ENBOX_NAMESPACES_LEN $(SRCDIR)/namespaces.in > $(@)

# Generate capability flags header
$(BUILDDIR)/capabilities.h: $(SRCDIR)/scripts/gen_flag_descs_header \
                            $(SRCDIR)/capabilities.in
	@echo "  GEN     $(@)"
	$(Q)$(<) -v macro=ENBOX_CAPABILITIES_LEN \
	         $(SRCDIR)/capabilities.in > $(@)

# Generate mounting flag descriptor table.
$(BUILDDIR)/mount_flags.i: $(SRCDIR)/scripts/gen_flag_descs_src \
                           $(SRCDIR)/mount_flags.in
	@echo "  GEN     $(@)"
	$(Q)$(^) > $(@)

# Generate namespace descriptor table.
$(BUILDDIR)/namespaces.i: $(SRCDIR)/scripts/gen_flag_descs_src \
                          $(SRCDIR)/namespaces.in
	@echo "  GEN     $(@)"
	$(Q)$(^) > $(@)

# Generate capability descriptor table.
$(BUILDDIR)/capabilities.i: $(SRCDIR)/scripts/gen_flag_descs_src \
                            $(SRCDIR)/capabilities.in
	@echo "  GEN     $(@)"
	$(Q)$(^) > $(@)

clean: clean-generated

.PHONY: clean-generated
clean-generated:
	$(call rm_recipe,$(BUILDDIR)/mount_flags.h)
	$(call rm_recipe,$(BUILDDIR)/mount_flags.i)
	$(call rm_recipe,$(BUILDDIR)/namespaces.h)
	$(call rm_recipe,$(BUILDDIR)/namespaces.i)
	$(call rm_recipe,$(BUILDDIR)/capabilities.h)
	$(call rm_recipe,$(BUILDDIR)/capabilities.i)

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

pkgconfigs          := libenbox.pc
libenbox.pc-tmpl    := libenbox_pkgconf_tmpl

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
