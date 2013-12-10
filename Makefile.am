ACLOCAL_AMFLAGS = -I m4

moddir = @APACHE_MODULEDIR@
mod_LTLIBRARIES = mod_cachebusting.la

mod_cachebusting_la_SOURCES = mod_cachebusting.c
mod_cachebusting_la_CFLAGS = @APACHE_CFLAGS@ @APACHE_INCLUDES@
mod_cachebusting_la_CPPFLAGS = @APACHE_CPPFLAGS@ @APACHE_INCLUDES@
mod_cachebusting_la_LDFLAGS = -avoid-version -module @APACHE_LDFLAGS@
mod_cachebusting_la_LIBS = @APACHE_LIBS@
