config-in           := Config.in
config-h            := enbox/config.h

common-cflags       := -Wall -Wextra -Wformat=2 $(EXTRA_CFLAGS)

solibs              := libenbox.so
libenbox.so-objs     = lib.o
libenbox.so-cflags   = $(common-cflags) -DPIC -fpic
libenbox.so-ldflags  = $(EXTRA_LDFLAGS) \
                       -shared -Bsymbolic -fpic -Wl,-soname,libenbox.so
libenbox.so-pkgconf := libutils

#bins                 = enbox
#enbox-objs           = enbox.c
#enbox-cflags         = $(common-cflags)
#enbox-ldflags       := $(EXTRA_LDFLAGS) -lenbox
#enbox-pkgconf       := libutils
#enbox-path          := $(SBINDIR)/enbox

HEADERDIR           := $(CURDIR)/include
headers              = enbox/enbox.h

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
