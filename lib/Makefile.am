#SUBDIRS = includes

#EXTRA_DIST = Makefile.msvc CMakeLists.txt version.rc.in

AM_CFLAGS = $(WARNCFLAGS) $(EXTRACFLAG)
#AM_CPPFLAGS = -I$(srcdir)/includes -I$(builddir)/includes -DBUILDING_NGHTTP2 \
#        @DEFS@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libhna.pc
DISTCLEANFILES = $(pkgconfig_DATA)

lib_LTLIBRARIES = libhna.la

#OBJECTS = find_next.cpp ssl_session.cpp base64url.cpp ldns_helpers.cpp knot_helpers.cpp ssl_helpers.cpp
OBJECTS = ssl_session.cpp ldns_helpers.cpp knot_helpers.cpp ssl_helpers.cpp

HFILES = ssl_session.h ldns_helpers.h knot_helpers.h ssl_helpers.h

libhna_la_SOURCES = $(HFILES) $(OBJECTS)
libhna_la_LDFLAGS = -no-undefined \
        -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

