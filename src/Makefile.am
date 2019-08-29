AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = $(ACLOCAL_FLAGS)
AM_CXXFLAGS = -fPIC -Wall -Wextra
AM_CXXFLAGS += -I/usr/local/include -I$(top_builddir)/thirdparty/nlohmann_json/single_include
AM_LDFLAGS = -L/usr/local/lib
#bin_PROGRAMS = dns_over_https_proxy homenet_dm homenet_hna
bin_PROGRAMS = homenet_dm homenet_hna
#bin_PROGRAMS = dns_over_https_proxy find_next
#dns_over_https_proxy_SOURCES = dns_over_https_proxy.cpp
#dns_over_https_proxy_LDADD = $(top_builddir)/lib/libhna.la
homenet_dm_SOURCES = homenet_dm.cpp
homenet_dm_LDADD = $(top_builddir)/lib/libhna.la
homenet_hna_SOURCES = homenet_hna.cpp
homenet_hna_LDADD = $(top_builddir)/lib/libhna.la
#find_next_SOURCES = find_next.cpp


