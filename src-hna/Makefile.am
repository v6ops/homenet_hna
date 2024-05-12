AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = $(ACLOCAL_FLAGS)
AM_CFLAGS = -fPIC -Wall -Wextra
AM_CFLAGS += -I/usr/local/include
AM_LDFLAGS = -L/usr/local/lib
bin_PROGRAMS = homenethna 
homenethna_SOURCES = homenet_hna.c
homenethna_LDADD = $(top_builddir)/lib/libhna.la -ljansson -lldns -lssl -lcrypto 
