PACKAGE       := enbox
VERSION       := 1.0
EXTRA_CFLAGS  := -O2 -DNDEBUG
EXTRA_LDFLAGS := -O2

export VERSION EXTRA_CFLAGS EXTRA_LDFLAGS

include $(EBUILDDIR)/main.mk
