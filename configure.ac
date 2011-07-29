AC_PREREQ([2.56])
AC_INIT([ssh2toronion], [0.1])

AM_INIT_AUTOMAKE([1.10])

AC_CONFIG_SRCDIR([src/ssh2toronion.c])


# HACK
# Workaround stupid autoconf CFLAGS default
# (Bash considers set but empty variables different from null for the ${VAR:+alt} operator)
CFLAGS="${CFLAGS}"

# Make cross compilation options available in --help
AC_CANONICAL_HOST

# Checks for programs.
AC_PROG_CC_STDC

# Variable fixes for older autoconf versions:
AS_IF([test -z "$docdir"],[
	AC_SUBST([docdir], [${datarootdir}/doc/${AC_PACKAGE_TARNAME}])
])

# Commandline options - enable:

# -O0 turns off all optimizations; this is necessary for accurate debugging
# Add later for stricter checking: -Wextra -Wmissing-declarations -Wstrict-prototypes
AC_ARG_ENABLE([debug],
	AS_HELP_STRING([--enable-debug[=yes/relaxed/profile/debugprofile/no]],[Compile debug version [yes]]),
	[ enable_debug=${enableval} ], [ enable_debug=yes ])
AC_MSG_CHECKING([whether to compile in debug mode])
AC_MSG_RESULT([${enable_debug}])

if test "x$enable_debug" = "xyes" ; then
	DEBUGFLAGS="${DEBUGFLAGS} -O0 -g -Wall -Werror -Wmissing-field-initializers -Wcast-align -Wwrite-strings"
	DEBUGFLAGS="${DEBUGFLAGS} -Wpointer-arith"
	ST_CFLAGS="${ST_CFLAGS} -Wmissing-declarations -Wstrict-prototypes"
	ST_CPPFLAGS="${ST_CPPFLAGS} -DDEBUG"
elif test "x$enable_debug" = "xrelaxed" ; then
	DEBUGFLAGS="${DEBUGFLAGS} -g -O0 -Wall -Wextra -Wwrite-strings"
	ST_CPPFLAGS="${ST_CPPFLAGS} -DDEBUG"
elif test "x$enable_debug" = "xdebugprofile" ; then
	DEBUGFLAGS="${DEBUGFLAGS} -g -O0 -pg -Wall -Wwrite-strings"
	ST_CPPFLAGS="${ST_CPPFLAGS} -DDEBUG"
	LDFLAGS="-pg ${LDFLAGS}"
elif test "x$enable_debug" = "xprofile" ; then
	DEBUGFLAGS="${DEBUGFLAGS} -g -Os -pg -Wall -Wwrite-strings"
	ST_CPPFLAGS="${ST_CPPFLAGS} -DNDEBUG"
	LDFLAGS="-pg ${LDFLAGS}"
else
	DEBUGFLAGS="${DEBUGFLAGS} -g -Wall -Wwrite-strings"
	ST_CPPFLAGS="${ST_CPPFLAGS} -DNDEBUG"
fi

AC_DEFINE_UNQUOTED([DEBUGOPT], ["$enable_debug"], [Debug option used when configuring.])

ST_CFLAGS="${ST_CFLAGS} ${DEBUGFLAGS}"
ST_CXXFLAGS="${ST_CXXFLAGS} ${DEBUGFLAGS}"


# Checks for libraries:
PKG_CHECK_MODULES([SSL_CRYPTO], [libcrypto])
PKG_CHECK_MODULES([SSH2], [libssh2])

AC_SUBST([ST_CPPFLAGS], [${ST_CPPFLAGS}])
AC_SUBST([ST_CFLAGS], [${ST_CFLAGS}])
AC_SUBST([ST_CXXFLAGS], [${ST_CXXFLAGS}])

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT

AS_IF([test "x$enable_debug" = "xyes"],[
	AC_MSG_NOTICE()
	AC_MSG_NOTICE([*** Running in debug mode! ***])
])
