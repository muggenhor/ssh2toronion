# Created by: Giel van Schijndel <me@mortis.eu>
# $FreeBSD$

PORTNAME=	ssh2toronion
PORTVERSION=	0.0.1
CATEGORIES=	security

MAINTAINER=	me@mortis.eu
COMMENT=	Proxy to route SSH onion connections through Tor

USE_GITHUB=	yes
GH_ACCOUNT=	muggenhor
GH_COMMIT=	3ae9eaa
GH_TAGNAME=	${GH_COMMIT}

BUILD_DEPENDS=	${LOCALBASE}/libdata/pkgconfig/libcrypto.pc:${PORTSDIR}/security/openssl \
		${LOCALBASE}/libdata/pkgconfig/libssh2.pc:${PORTSDIR}/security/libssh2 \
		pkg-config:${PORTSDIR}/devel/pkgconf

LIB_DEPENDS=	libcrypto.so.8:${PORTSDIR}/security/openssl \
		libssh2.so.1:${PORTSDIR}/security/libssh2

USE_AUTOTOOLS=	aclocal autoheader autoconf automake
ACLOCAL_ARGS=	-I m4
AUTOMAKE_ARGS=	-a -c --foreign
CONFIGURE_ARGS+= --disable-debug

.include <bsd.port.mk>
