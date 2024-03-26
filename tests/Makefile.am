
# Copyright (c) 2019 Ray Hunter

# dns_over_https_proxy
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
#
if HAVE_CUNIT

check_PROGRAMS = main sample_test

# complex test made up of several source files in one suite
OBJECTS = main.cpp ldns_helpers_test.cpp
HFILES = ldns_helpers_test.h
main_SOURCES = $(HFILES) $(OBJECTS)

#if ENABLE_STATIC
# main_LDADD = ${top_builddir}/lib/libhna.la
#else
# With static lib disabled and symbol hiding enabled, we have to link object
# files directly because the tests use symbols not included in public API.
main_LDADD = ${top_builddir}/lib/*.o
#main_LDADD = ${top_builddir}/src/find_next.o
#endif

main_LDADD += @CUNIT_LIBS@
main_LDFLAGS = -static

# stand alone test
SAMPLE_OBJECTS = sample_test.cpp
SAMPLE_HFILES = 
sample_test_SOURCES = $(SAMPLE_HFILES) $(SAMPLE_OBJECTS)
sample_test_LDADD = @CUNIT_LIBS@

TESTS = main sample_test
endif # HAVE_CUNIT
