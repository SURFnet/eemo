# $Id$

AC_DEFUN([ACX_DLOPEN],[
  AC_CHECK_FUNC(dlopen, [AC_DEFINE(HAVE_DLOPEN,1,[Define if dlopen is available])],
  [
    AC_CHECK_LIB([dl],[dlopen], 
      [AC_DEFINE(HAVE_DLOPEN,1,[Define if dlopen is available])
      LIBS="$LIBS -ldl"],
      [AC_CHECK_FUNC(LoadLibrary, 
        [if test $ac_cv_func_LoadLibrary = yes; then
          AC_DEFINE(HAVE_LOADLIBRARY, 1, [Define whether LoadLibrary is available (win32)])
        fi
        ], [AC_MSG_ERROR(No dynamic library loading support)]
      )]
    )
  ])
])
