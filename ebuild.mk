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
Version: $(VERSION)
Requires:
Cflags: -I$${includedir}
Libs: -L$${libdir} -lenbox
endef

pkgconfigs          := libenbox.pc
libenbox.pc-tmpl    := libenbox_pkgconf_tmpl

################################################################################
# Documentation generation
################################################################################

.PHONY: doxy
doxy: | $(BUILDDIR)/doc/doxy
	@echo "  DOXY    $(|)"
	$(Q)env OUTDIR="$(|)" \
	        INCDIR="$(patsubst -I%,%,$(filter -I%,$(common-cflags)))" \
	        VERSION="$(VERSION)" \
	        $(if $(Q),QUIET="YES",QUIET="NO") \
	    doxygen $(SRCDIR)/doc/Doxyfile

$(BUILDDIR)/doc/doxy:
	@mkdir -p $(@)

clean: clean-doxy

.PHONY: clean-doxy
clean-doxy:
	$(call rmr_recipe,$(BUILDDIR)/doc/doxy)

DOXYREST := /opt/doxyrest/bin/doxyrest

define rest_recipe
@echo "  REST    $(strip $(2))"
$(Q)$(DOXYREST) --config=$(SRCDIR)/doc/doxyrest/conf.lua \
                --output=$(strip $(2)) \
                $(strip $(1))
endef

.PHONY: rest
rest: doxy
	$(call rest_recipe,$(BUILDDIR)/doc/doxy/xml/index.xml,\
	                   $(SRCDIR)/doc/api/index.rst)

clean: clean-rest

.PHONY: clean-rest
clean-rest:
	$(call rmr_recipe,$(SRCDIR)/doc/api)

SPHINXBUILD := sphinx-build

define html_recipe
@echo "  HTML    $(strip $(2))"
$(Q)$(if $(3),env $(3)) \
    $(SPHINXBUILD) -M html \
                   "$(strip $(1))" \
                   "$(strip $(2))" \
                   $(if $(Q),-Q,-q) \
                   -a \
                   -E \
                   -j 1
endef

sphinx_env  := VERSION="$(VERSION)" \
               DOXY_XML_PATH="$(BUILDDIR)/doc/doxy/xml"

.PHONY: html
html: rest
	$(call html_recipe,$(SRCDIR)/doc,$(BUILDDIR)/doc,$(sphinx_env))

clean: clean-html

.PHONY: clean-html
clean-html:
	$(call rmr_recipe,$(BUILDDIR)/doc/html)
	$(call rmr_recipe,$(BUILDDIR)/doc/doctrees)
