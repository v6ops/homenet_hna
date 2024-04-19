# AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
AM_CXXFLAGS = -fPIC -Wall -Wextra
AM_CXXFLAGS += -I/usr/local/include -I/usr/local/include/nlohmann -I$(top_builddir)/thirdparty/nlohmann_json/single_include
AM_LDFLAGS = -L/usr/local/lib
# SUBDIRS = src doc tests examples man scripts
SUBDIRS = lib src tests 
dist_doc_DATA = README

