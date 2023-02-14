override PACKAGE := enbox
override VERSION := 1.0
EXTRA_CFLAGS     := -O2 -DNDEBUG
EXTRA_LDFLAGS    := -O2

export VERSION EXTRA_CFLAGS EXTRA_LDFLAGS

EBUILDDIR ?= /usr/share/ebuild
ifeq ($(realpath $(EBUILDDIR)/main.mk),)
$(error '$(EBUILDDIR)': no valid Ebuild install found !)
endif

include $(EBUILDDIR)/main.mk
