AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = $(ACLOCAL_FLAGS)
AM_CFLAGS = -fPIC -Wall -Wextra
AM_CFLAGS += -I/usr/local/include
AM_LDFLAGS = -L/usr/local/lib -L.
# multiple builds. Pick your poison. Some simpler versions for debug and test
bin_PROGRAMS = server serverssl libevent_dm libevent_tofu homenet_dm homenet_tofu testdb
# single thread echo server libevent
server_SOURCES = server.c workqueue.c
# single thread echo server libevent with ssl
serverssl_SOURCES = server-ssl.c workqueue.c util.c 
serverssl_LDADD = $(top_builddir)/lib/libhna.la -lssl -lcrypto
# simple DB test
testdb_SOURCES = testdb.c dm_tofu.c db.c
testdb_LDADD = -lmysqlclient
testdb_CFLAGS= -I/usr/include/mysql $(AM_CFLAGS)
# single thread DM based on libevent, TLS, TOFU (Trust on First Use)
libevent_tofu_SOURCES = libevent_dm.c dm_worker.c dm_tofu.c db.c util.c
libevent_tofu_LDADD = $(top_builddir)/lib/libhna.la -lssl -lcrypto -lmysqlclient
libevent_tofu_CFLAGS= -DWITH_SSL -DWITH_TOFU -DWITH_IPv6 $(AM_CFLAGS)
# single thread DM based on libevent, TLS, no TOFU (Trust on First Use)
libevent_dm_SOURCES = libevent_dm.c dm_worker.c util.c
libevent_dm_LDADD = $(top_builddir)/lib/libhna.la -lssl -lcrypto
libevent_dm_CFLAGS= -DWITH_SSL $(AM_CFLAGS)
# multi thread DM based on libevent, TLS, no TOFU (Trust on First Use)
homenet_dm_SOURCES = homenet_dm.c workqueue.c dm_worker.c util.c dnsovertls.c
homenet_dm_LDADD = $(top_builddir)/lib/libhna.la -lssl -lcrypto
homenet_dm_CFLAGS= -DWITH_SSL -DWITH_DNSOVERTLS $(AM_CFLAGS)
# multi thread DM based on libevent, TLS, TOFU (Trust on First Use)
homenet_tofu_SOURCES = homenet_dm.c workqueue.c dm_worker.c util.c dm_tofu.c db.c dnsovertls.c
homenet_tofu_LDADD = $(top_builddir)/lib/libhna.la -lssl -lcrypto -lmysqlclient
homenet_tofu_CFLAGS= -DWITH_SSL -DWITH_TOFU -DWITH_DNSOVERTLS $(AM_CFLAGS)
