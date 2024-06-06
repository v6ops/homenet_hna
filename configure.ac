AC_PREREQ([2.69])
# The first parameter is project name
# second is version number
# third is bug report address
AC_INIT([homenet_dm], [1.0])

# Check for C compiler
#AC_PROG_CXX
AC_PROG_CC
AM_PROG_AR
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
LT_INIT


AC_CONFIG_MACRO_DIRS([m4])
#m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

dnl See versioning rule:
dnl  http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
AC_SUBST(LT_CURRENT, 0)
AC_SUBST(LT_REVISION, 1)
AC_SUBST(LT_AGE, 0)

major=`echo $PACKAGE_VERSION |cut -d. -f1 | sed -e "s/[^0-9]//g"`
minor=`echo $PACKAGE_VERSION |cut -d. -f2 | sed -e "s/[^0-9]//g"`
patch=`echo $PACKAGE_VERSION |cut -d. -f3 | cut -d- -f1 | sed -e "s/[^0-9]//g"`

PACKAGE_VERSION_NUM=`printf "0x%02x%02x%02x" "$major" "$minor" "$patch"`

AC_SUBST(PACKAGE_VERSION_NUM)

# Checks for libraries.
LT_INIT
AC_ENABLE_SHARED
AC_DISABLE_STATIC
AC_PROG_LIBTOOL(libtool)
AC_CHECK_LIB([ssl], [main], [], [echo "openssl ssl library not found.  Please install openssl ssl library before proceeding"; exit -1])
AC_CHECK_LIB([crypto], [main], [], [echo "openssl crypto library not found.  Please install openssl crypto library before proceeding"; exit -1])
AC_CHECK_LIB([ldns], [main], [], [echo "ldns DNS library not found.  Please install NLnet Labs ldns library before proceeding"; exit -1])
AC_CHECK_LIB([event], [main], [], [echo "libevent library not found.  Please install libevent library before proceeding"; exit -1])
AC_CHECK_HEADERS(event2/event.h event2/dns.h event2/bufferevent_ssl.h)
AC_CHECK_LIB([event_openssl], [main], [], [echo "event_openssl library not found.  Please install event_openssl library before proceeding"; exit -1])
AC_CHECK_HEADERS(jansson_config.h  jansson.h)
AC_CHECK_LIB([jansson], [main], [], [echo "jansson JSON library not found.  Please install jansson library before proceeding"; exit -1])
# this is bad but the check header doesn't seem to work with .hpp
AC_CHECK_LIB([pthread], [main], [], [echo "libpthread library not found.  Please install libpthread library before proceeding"; exit -1])
#AC_CHECK_FILE(
#    /usr/local/include/nlohmann/json.hpp,
#    [],
#    [AC_MSG_ERROR([Could not find nlohmann/json.hpp])]
#)
AX_CXX_COMPILE_STDCXX_11
#AC_CHECK_HEADER(
#    "nlohmann/json.hpp",
#    [],
#    [AC_MSG_ERROR([Could not find nlohmann/json.hpp])]
#)

# cunit
AC_CHECK_LIB([cunit], [CU_initialize_registry],
               [have_cunit=yes], [have_cunit=no])
if test "x${have_cunit}" = "xyes"; then
    CUNIT_LIBS="-lcunit"
    CUNIT_CFLAGS=""
    AC_SUBST([CUNIT_LIBS])
    AC_SUBST([CUNIT_CFLAGS])
fi
    AM_CONDITIONAL([HAVE_CUNIT], [ test "x${have_cunit}" = "xyes" ])


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])


# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset select socket strerror])

# Safety checks in case user overwritten --srcdir
AC_CONFIG_SRCDIR([src-dm/homenet_dm.c])

# Store the auxiliary build tools (e.g., install-sh, config.sub, config.guess)
# in this dir (build-aux)
# AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])

# Init automake, and specify this program use relaxed structures.
# i.e. this program doesn't follow the gnu coding standards, and doesn't have
# ChangeLog, COPYING, AUTHORS, INSTALL, README etc. files.
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# We can add more checks in this section

# Tells automake to create a Makefile
# See https://www.gnu.org/software/automake/manual/html_node/Requirements.html
AC_CONFIG_FILES([
 Makefile
 lib/Makefile
 src/Makefile
 tests/Makefile
 src-dm/Makefile
 src-hna/Makefile
])
# Generate the output
AC_OUTPUT
