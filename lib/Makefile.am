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
OBJECTS = ssl_session.cpp ldns_helpers.cpp knot_helpers.cpp ssl_helpers.cpp workqueue.cpp

HFILES = ssl_session.h ldns_helpers.h knot_helpers.h ssl_helpers.h workqueue.h

# Start with version information of 0:0:0 for each libtool library.
# Update the version information only immediately before a public release of your software. More frequent updates are unnecessary, and only guarantee that the current interface number gets larger faster.
# If the library source code has changed at all since the last update, then increment revision (c:r:a becomes c:r+1:a).
# If any interfaces have been added, removed, or changed since the last update, increment current, and set revision to 0.
# If any interfaces have been added since the last public release, then increment age.
# If any interfaces have been removed or changed since the last public release, then set age to 0.
LT_CURRENT=1
LT_REVISION=0
LT_AGE=0

libhna_la_SOURCES = $(HFILES) $(OBJECTS)
libhna_la_LDFLAGS = -no-undefined \
        -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

