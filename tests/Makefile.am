
# Copyright (c) 2019 Ray Hunter
#
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
AUTOMAKE_OPTIONS = subdir-objects
if HAVE_CUNIT

check_PROGRAMS = main sample_test


# complex test made up of several source files in one suite
#OBJECTS = main.cpp ldns_helpers_test.cpp
OBJECTS = main.c ldns_helpers_test.c dm_tofu_test.c dm_worker_test.c do_EVP_HMACSHA256_test.c test_harness.c ../src-dm/dm_tofu.c ../src-dm/dm_worker.c  ../src-dm/db.c
HFILES = ldns_helpers_test.h dm_tofu_test.h dm_worker_test.h do_EVP_HMACSHA256_test.h test_harness.h ../src-dm/db.h ../src-dm/dm_tofu.h ../src-dm/dm_worker.h 
main_SOURCES = $(HFILES) $(OBJECTS)

#if ENABLE_STATIC
# main_LDADD = ${top_builddir}/lib/libhna.la
#else
# With static lib disabled and symbol hiding enabled, we have to link object
# files directly because the tests use symbols not included in public API.
main_LDADD = ${top_builddir}/lib/*.o
#main_LDADD = ${top_builddir}/src/find_next.o
#endif

main_LDADD += @CUNIT_LIBS@ -lssl -lcrypto -lmysqlclient -lldns -lhna 
main_LDFLAGS = -static  -fsanitize=address
main_CFLAGS= -DWITH_SSL -DWITH_TOFU $(AM_CFLAGS)

# stand alone test
SAMPLE_OBJECTS = sample_test.c
SAMPLE_HFILES = 
sample_test_SOURCES = $(SAMPLE_HFILES) $(SAMPLE_OBJECTS)
sample_test_LDADD = @CUNIT_LIBS@

# stand alone test for dm_worker (can't use underscores in name)
# DMWORKER_OBJECTS = dm_worker_test.c ../src-dm/dm_tofu.c ../src-dm/db.c test_harness.c
# DMWORKER_HFILES = dm_worker_test.h test_harness.h ../src-dm/db.h
# dmworker_SOURCES = $(DMWORKER_HFILES) $(DMWORKER_OBJECTS)
# dmworker_LDADD = @CUNIT_LIBS@ -lssl -lcrypto -lmysqlclient -lldns -lhna
# dmworker_LDFLAGS = -static  -fsanitize=address
# dmworker_CFLAGS= -DWITH_SSL -DWITH_TOFU $(AM_CFLAGS)


TESTS = main sample_test
endif # HAVE_CUNIT
