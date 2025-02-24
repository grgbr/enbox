################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Enbox.
# Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

common-cflags       := -Wall \
                       -Wextra \
                       -Wformat=2 \
                       -Wconversion \
                       -Wundef \
                       -Wshadow \
                       -Wcast-qual \
                       -Wcast-align \
                       -Wmissing-declarations \
                       -D_GNU_SOURCE \
                       -I ../include \
                       $(EXTRA_CFLAGS)

ifneq ($(filter y,$(CONFIG_ENBOX_ASSERT_API)),)
common-cflags       := $(filter-out -DNDEBUG,$(common-cflags))
common-ldflags      := $(filter-out -DNDEBUG,$(common-ldflags))
endif # ($(filter y,$(CONFIG_ENBOX_ASSERT_API)),)

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
$(BUILDDIR)/mount_flags.h: $(TOPDIR)/scripts/gen_flag_descs_header \
                           $(SRCDIR)/mount_flags.in
	@echo "  GEN     $(@)"
	$(Q)$(<) -v macro=ENBOX_MOUNT_FLAGS_LEN $(SRCDIR)/mount_flags.in > $(@)

# Generate mounting flags header
$(BUILDDIR)/namespaces.h: $(TOPDIR)/scripts/gen_flag_descs_header \
                          $(SRCDIR)/namespaces.in
	@echo "  GEN     $(@)"
	$(Q)$(<) -v macro=ENBOX_NAMESPACES_LEN $(SRCDIR)/namespaces.in > $(@)

# Generate capability flags header
$(BUILDDIR)/capabilities.h: $(TOPDIR)/scripts/gen_flag_descs_header \
                            $(SRCDIR)/capabilities.in
	@echo "  GEN     $(@)"
	$(Q)$(<) -v macro=ENBOX_CAPABILITIES_LEN \
	         $(SRCDIR)/capabilities.in > $(@)

# Generate mounting flag descriptor table.
$(BUILDDIR)/mount_flags.i: $(TOPDIR)/scripts/gen_flag_descs_src \
                           $(SRCDIR)/mount_flags.in
	@echo "  GEN     $(@)"
	$(Q)$(^) > $(@)

# Generate namespace descriptor table.
$(BUILDDIR)/namespaces.i: $(TOPDIR)/scripts/gen_flag_descs_src \
                          $(SRCDIR)/namespaces.in
	@echo "  GEN     $(@)"
	$(Q)$(^) > $(@)

# Generate capability descriptor table.
$(BUILDDIR)/capabilities.i: $(TOPDIR)/scripts/gen_flag_descs_src \
                            $(SRCDIR)/capabilities.in
	@echo "  GEN     $(@)"
	$(Q)$(^) > $(@)

clean: _clean-generated

.PHONY: _clean-generated
_clean-generated:
	$(call rm_recipe,$(BUILDDIR)/mount_flags.h)
	$(call rm_recipe,$(BUILDDIR)/mount_flags.i)
	$(call rm_recipe,$(BUILDDIR)/namespaces.h)
	$(call rm_recipe,$(BUILDDIR)/namespaces.i)
	$(call rm_recipe,$(BUILDDIR)/capabilities.h)
	$(call rm_recipe,$(BUILDDIR)/capabilities.i)

# ex: filetype=make :
