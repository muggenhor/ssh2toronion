AM_CPPFLAGS = $(SSL_CRYPTO_CFLAGS) $(SSH2_CFLAGS) $(ST_CPPFLAGS)
AM_CFLAGS = $(ST_CFLAGS)

bin_PROGRAMS = ssh2toronion

ssh2toronion_SOURCES = \
	ssh2toronion.c

ssh2toronion_LDADD = \
	$(SSL_CRYPTO_LIBS) \
	$(SSH2_LIBS)
