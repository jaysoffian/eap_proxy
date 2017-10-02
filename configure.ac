# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.59)

m4_define([VERSION_ID], [m4_esyscmd([
	if test -f .version ; then
	    head -n 1 .version | tr -d \\n
	else
	    echo -n 2.4
	fi])])
AC_INIT([vyatta-eap-proxy], VERSION_ID)

test -n "$VYATTA_VERSION" || VYATTA_VERSION=$PACKAGE_VERSION

AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE([gnu no-dist-gzip dist-bzip2 subdir-objects])
AC_PREFIX_DEFAULT([/opt/vyatta])

AC_ARG_ENABLE([nostrip],
	AC_HELP_STRING([--enable-nostrip],
	[include -nostrip option during packaging]),
	[NOSTRIP=-nostrip], [NOSTRIP=])

AC_CONFIG_FILES([Makefile])

AC_SUBST(NOSTRIP)

AC_PROG_CC
AC_PROG_CXX
AM_PROG_AS
AM_PROG_CC_C_O
AC_OUTPUT

