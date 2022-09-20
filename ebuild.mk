config-in           := Config.in
config-h            := enbox/config.h

common-cflags       := -Wall -Wextra -Wformat=2 $(EXTRA_CFLAGS)

solibs              := libenbox.so
libenbox.so-objs     = lib.o conf.o
libenbox.so-cflags   = $(common-cflags) -DPIC -fpic
libenbox.so-ldflags  = $(EXTRA_LDFLAGS) \
                       -shared -Bsymbolic -fpic -Wl,-soname,libenbox.so
libenbox.so-pkgconf := libelog libutils libconfig

bins                 = enbox-skel
enbox-skel-objs      = skel.o
enbox-skel-cflags    = $(common-cflags)
enbox-skel-ldflags   = $(EXTRA_LDFLAGS) -lenbox
enbox-skel-pkgconf  := libelog libutils
enbox-skel-path     := $(SBINDIR)/enbox-skel

HEADERDIR           := $(CURDIR)/include
headers              = enbox/enbox.h

$(addprefix $(BUILDDIR)/,$(libenbox.so-objs)): $(SRCDIR)/common.h
$(addprefix $(BUILDDIR)/,$(enbox-skel-objs)): $(SRCDIR)/common.h

# Common definitions depend on generated mounting flag definitions.
$(SRCDIR)/common.h: $(BUILDDIR)/mount_flags.h $(BUILDDIR)/namespaces.h

# Configuration object depends on generated mounting flag descriptor table.
$(BUILDDIR)/conf.o: $(BUILDDIR)/mount_flags.i $(BUILDDIR)/namespaces.i

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

clean: clean-generated

.PHONY: clean-generated
clean-generated:
	$(call rm_recipe,$(BUILDDIR)/mount_flags.h)
	$(call rm_recipe,$(BUILDDIR)/mount_flags.i)
	$(call rm_recipe,$(BUILDDIR)/namespaces.h)
	$(call rm_recipe,$(BUILDDIR)/namespaces.i)

define libenbox_pkgconf_tmpl
prefix=$(PREFIX)
exec_prefix=$${prefix}
libdir=$${exec_prefix}/lib
includedir=$${prefix}/include

Name: libenbox
Description: Embedded sandboxing library
Version: %%PKG_VERSION%%
Requires:
Cflags: -I$${includedir}
Libs: -L$${libdir} -lenbox
endef

pkgconfigs          := libenbox.pc
libenbox.pc-tmpl    := libenbox_pkgconf_tmpl
