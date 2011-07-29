#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <libssh2.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sysexits.h>
#include <unistd.h>

static const uint8_t SOCKS_OP_CONNECT = 1;
struct socks4_connect_op
{
	uint8_t  version;
	uint8_t  command;
	uint16_t dstport;
	uint32_t dstip;
	char     userid_host[];
};

struct socks4_connect_reply
{
	uint8_t  version;
	uint8_t  command;
	uint16_t dstport;
	uint32_t dstip;
};

static void base32_encode(char* dest, size_t destlen, const char* src, size_t srclen)
{
	static const char BASE32_CHARS[] = "abcdefghijklmnopqrstuvwxyz234567";
	unsigned int i, bit, v, u;
	size_t nbits = srclen * 8;

	for (i=0,bit=0; bit < nbits && i < destlen; ++i, bit+=5) {
		/* set v to the 16-bit value starting at src[bits/8], 0-padded. */
		v = ((uint8_t)src[bit/8]) << 8;
		if (bit+5<nbits) v += (uint8_t)src[(bit/8)+1];
		/* set u to the 5-bit value at the bit'th bit of src. */
		u = (v >> (11-(bit%8))) & 0x1F;
		dest[i] = BASE32_CHARS[u];
	}
	dest[i] = '\0';
}

static void writeall(const int fd, const void* buf, size_t len)
{
	while (len)
	{
		const ssize_t ret = write(fd, buf, len);
		if (ret == -1)
		{
			if (errno == EINTR)
				continue;

			perror("write");
			exit(EX_IOERR);
		}

		buf += ret;
		len -= ret;
	}
}

static ssize_t readall(const int fd, void* buf, size_t len)
{
	size_t cnt = 0;
	while (len)
	{
		const ssize_t ret = read(fd, buf, len);
		if (ret == -1)
		{
			if (errno == EINTR)
				continue;

			perror("read");
			exit(EX_IOERR);
		}

		if (ret == 0)
			return cnt;

		buf += ret;
		len -= ret;
		cnt += ret;
	}

	return cnt;
}

static int socks_connect(const char* const hostname, const int port)
{
	const struct sockaddr_in tor_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(9050),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	const int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1)
	{
		perror("socket(AF_INET)");
		exit(EX_OSERR);
	}

	if (connect(sock, (const struct sockaddr*)&tor_addr, sizeof(tor_addr)) == -1)
	{
		perror("connect(127.0.0.1:9050)");
		exit(EX_IOERR);
	}

	const size_t cmd_len = sizeof(struct socks4_connect_op) + 1 + strlen(hostname) + 1;
	struct socks4_connect_op* const socks4_connect_op = malloc(cmd_len);
	socks4_connect_op->version = 4;
	socks4_connect_op->command = SOCKS_OP_CONNECT;
	socks4_connect_op->dstport = htons(port);
	socks4_connect_op->dstip   = htonl(1);
	socks4_connect_op->userid_host[0] = '\0';
	strcpy(&socks4_connect_op->userid_host[1], hostname);
	writeall(sock, socks4_connect_op, cmd_len);
	free(socks4_connect_op);

	struct socks4_connect_reply reply;
	ssize_t ret = readall(sock, &reply, sizeof(reply));
	if (ret < (ssize_t)sizeof(reply))
	{
		fputs("premature EOF during SOCKS handshake.\n", stderr);
		exit(EX_PROTOCOL);
	}

	if (reply.version != 0)
	{
		fputs("invalid SOCKS reply\n", stderr);
		exit(EX_PROTOCOL);
	}

	switch (reply.command)
	{
		case 90:
			return sock;

		case 91:
			fputs("SOCKS request rejected or failed\n", stderr);
			exit(EX_UNAVAILABLE);
		case 92:
			fputs("SOCKS request rejected because SOCKS server cannot connect to local identd on client host.\n", stderr);
			exit(EX_UNAVAILABLE);
		case 93:
			fputs("SOCKS request rejected because SOCKS client and identd report different user ids\n", stderr);
			exit(EX_NOUSER);
		default:
			fprintf(stderr, "Unknown SOCKS reply code: %hhu\n", reply.command);
			exit(EX_PROTOCOL);
	}
}

static int tunnel(const char* const hostname, const int port)
{
	const int sock = socks_connect(hostname, port);

	bool stdin_open   = true,
	     stdout_open  = true,
	     sockin_open  = true,
	     sockout_open = true;
	char stdoutbuf [1 << 16],
	     sockoutbuf[1 << 16];
	size_t stdoutpending  = 0,
	       sockoutpending = 0;

	while (stdin_open || stdout_open || sockin_open || sockout_open)
	{
		fd_set rfds, wfds;
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);

		if (stdin_open && sockoutpending < sizeof(sockoutbuf))
			FD_SET(STDIN_FILENO, &rfds);
		if (stdout_open && stdoutpending)
			FD_SET(STDOUT_FILENO, &wfds);

		if (sockin_open && stdoutpending < sizeof(stdoutpending))
			FD_SET(sock, &rfds);
		if (sockout_open && sockoutpending)
			FD_SET(sock, &wfds);

		const int ret = select(sock + 1, &rfds, &wfds, NULL, NULL);
		if (ret == -1)
		{
			if (errno == EINTR)
				continue;
			perror("select");
			return EX_OSERR;
		}

		// Send data down the socket first
		if (sockoutpending && FD_ISSET(sock, &wfds))
		{
			ssize_t ret = write(sock, sockoutbuf, sockoutpending);
			if (ret == -1)
			{
				switch (errno)
				{
					case EINTR:
						break;
					case ECONNRESET:
					case EPIPE:
						shutdown(sock, SHUT_WR);
						sockout_open = false;
						break;
					default:
						perror("send");
						return EX_IOERR;
				}
			}
			else
			{
				sockoutpending -= ret;
				memmove(sockoutbuf, sockoutbuf + ret, sockoutpending);
			}
		}

		// Send data down the pipe next
		if (stdoutpending && FD_ISSET(STDOUT_FILENO, &wfds))
		{
			ssize_t ret = write(STDOUT_FILENO, stdoutbuf, stdoutpending);
			if (ret == -1)
			{
				switch (errno)
				{
					case EINTR:
						break;
					case ECONNRESET:
					case EPIPE:
						close(STDOUT_FILENO);
						stdout_open = false;
						break;
					default:
						perror("write");
						return EX_IOERR;
				}
			}
			else
			{
				stdoutpending -= ret;
				memmove(stdoutbuf, stdoutbuf + ret, stdoutpending);
			}
		}

		// Fetch data from the socket first
		if (stdoutpending < sizeof(stdoutbuf) && FD_ISSET(sock, &rfds))
		{
			ssize_t ret = read(sock, stdoutbuf + stdoutpending, sizeof(stdoutbuf) - stdoutpending);
			if (ret == -1)
			{
				switch (errno)
				{
					case EINTR:
						break;
					default:
						perror("recv");
						return EX_IOERR;
				}
			}
			else if (ret == 0)
			{
				shutdown(sock, SHUT_RD);
				sockin_open = false;
			}
			else
			{
				stdoutpending += ret;
			}
		}

		// Fetch data from the pipe next
		if (sockoutpending < sizeof(sockoutbuf) && FD_ISSET(STDIN_FILENO, &rfds))
		{
			ssize_t ret = read(STDIN_FILENO, sockoutbuf + sockoutpending, sizeof(sockoutbuf) - sockoutpending);
			if (ret == -1)
			{
				switch (errno)
				{
					case EINTR:
						break;
					default:
						perror("read");
						return EX_IOERR;
				}
			}
			else if (ret == 0)
			{
				close(STDIN_FILENO);
				stdin_open = false;
			}
			else
			{
				sockoutpending += ret;
			}
		}

		// Close our output channels when the other input channels are closed (i.e. they're won't be any new data to send
		if (stdout_open && !stdoutpending && !sockin_open)
		{
			close(STDOUT_FILENO);
			stdout_open = false;
		}
		if (sockout_open && !sockoutpending && !stdin_open)
		{
			shutdown(sock, SHUT_WR);
			sockout_open = false;
		}

		// Close our input channels when the respective output channels are closed
		if (stdin_open && !sockout_open)
		{
			close(STDIN_FILENO);
			stdin_open = false;
		}
		if (sockin_open && !stdout_open)
		{
			shutdown(sock, SHUT_RD);
			sockin_open = false;
		}
	}

	return EX_OK;
}

int main(int argc, char** argv)
{
	int ret;

	ret = libssh2_init(0);
	if (ret != LIBSSH2_ERROR_NONE)
	{
		fprintf(stderr, "Failed to initialize libssh2: %d\n", ret);
		return EX_SOFTWARE;
	}

	static const char rel_known_hosts_path[] = "/.ssh/known_hosts";
	const char* const home_dir = getenv("HOME");
	if (!home_dir)
	{
		fputs("Required environment variable 'HOME' not found.\n", stderr);
		return EX_DATAERR;
	}

	char* const known_hosts_path = malloc(strlen(home_dir) + sizeof(rel_known_hosts_path));
	strcpy(known_hosts_path, home_dir);
	strcat(known_hosts_path, rel_known_hosts_path);

	LIBSSH2_SESSION* const session = libssh2_session_init();
	LIBSSH2_KNOWNHOSTS* known_hosts = libssh2_knownhost_init(session);
	ret = libssh2_knownhost_readfile(known_hosts, known_hosts_path, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
	if (ret < 0)
	{
		fprintf(stderr, "Error while reading known-hosts from '%s': %d\n", known_hosts_path, ret);
		return EX_DATAERR;
	}

	const char* const dsthost = argv[1];
	char* portend;
	int dstport = 22;
	if (argc >= 3)
	{
		dstport = strtoul(argv[2], &portend, 10);
		if (*argv[2] == '\0' || *portend != '\0')
		{
			fprintf(stderr, "invalid number as second parameter (target port number): '%s'\n", argv[2]);
			return EX_DATAERR;
		}
	}

	// Check if there's already an RSA key for the given host present
	struct libssh2_knownhost* cur_host = NULL;
	while (!libssh2_knownhost_get(known_hosts, &cur_host, cur_host))
	{
		if (cur_host->typemask & LIBSSH2_KNOWNHOST_KEY_SSHRSA
		 && cur_host->name
		 && strcmp(cur_host->name, argv[1]) == 0)
		{
			libssh2_knownhost_free(known_hosts);
			libssh2_session_free(session);
			libssh2_exit();
			free(known_hosts_path);
			return tunnel(dsthost, dstport);
		}
	}
	libssh2_knownhost_free(known_hosts);

	const int sock = socks_connect(dsthost, dstport);
	libssh2_banner_set(session, "SSH-2.0-ssh2onion_address_0.1");
	ret = libssh2_session_startup(session, sock);
	if (ret != LIBSSH2_ERROR_NONE)
	{
		fprintf(stderr, "Failure establishing SSH session: %d\n", ret);
		return EX_SOFTWARE;
	}

	void* keybuf;
	size_t size;
	{
		int type;
		const char* const key = libssh2_session_hostkey(session, &size, &type);

		if (type != LIBSSH2_HOSTKEY_TYPE_RSA)
		{
			fprintf(stderr, "Unexpected SSH key type\n");
			return EX_SOFTWARE;
		}

		keybuf = malloc(size);
		memcpy(keybuf, key, size);
	}
	libssh2_session_disconnect(session, "Finished.");
	close(sock);

	uint32_t len;
	if (size < sizeof(len))
	{
		fputs("invalidly encoded public RSA key.\n", stderr);
		return EX_DATAERR;
	}

	void* keyp = keybuf;
	size_t left = size;

	len = ntohl(*(const uint32_t*)keyp);
	left -= sizeof(len);
	keyp += sizeof(len);
	if (size < len)
	{
		fputs("invalidly encoded public RSA key.\n", stderr);
		return EX_DATAERR;
	} else if (strncmp("ssh-rsa", (const char*)keyp, len))
	{
		((char*)keyp)[len] = '\0';
		fprintf(stderr, "unknown key-format (expected \"ssh-rsa\"): \"%s\"\n", (const char*)keyp);
		return EX_DATAERR;
	}
	left -= len;
	keyp += len;

	len = ntohl(*(const uint32_t*)keyp);
	left -= sizeof(len);
	keyp += sizeof(len);
	if (size < len)
	{
		fputs("invalidly encoded public RSA key.\n", stderr);
		return EX_DATAERR;
	}

	RSA* const key = RSA_new();
	key->e = BN_bin2bn((const unsigned char*)keyp, len, NULL);
	left -= len;
	keyp += len;

	len = ntohl(*(const uint32_t*)keyp);
	left -= sizeof(len);
	keyp += sizeof(len);
	if (size < len)
	{
		fputs("invalidly encoded public RSA key.\n", stderr);
		return EX_DATAERR;
	}
	key->n = BN_bin2bn((const unsigned char*)keyp, len, NULL);

	// Encode the public key as PKCS#1
	const int keylen = i2d_RSAPublicKey(key, NULL);
	if (keylen < 0)
	{
		fputs("failed to read RSA public key\n", stderr);
		return EX_SOFTWARE;
	}
	unsigned char* const buf = malloc(keylen + 1);
	unsigned char* bufp = buf;
	assert(buf != NULL);
	if (keylen != i2d_RSAPublicKey(key, &bufp))
	{
		fputs("failed to read RSA public key\n", stderr);
		return EX_SOFTWARE;
	}
	RSA_free(key);

	// Take the SHA-1 digest from the PKCS#1 encoded key
	unsigned char digest[20];
	if (SHA1((const unsigned char*)buf, keylen, digest) == NULL)
	{
		fputs("failed to compute SHA-1 digest\n", stderr);
		return EX_SOFTWARE;
	}
	free(buf);

	// Base32 encode the SHA-1 digest, then trucate it to get the onion address
	static const char tld[] = ".onion";
	char onion[16 + sizeof(tld)];
	base32_encode(onion, 16 + 1, (const char*)digest, 10);
	strcat(onion, tld);

	static const char comment[] = "Tor Key";
	char knownhost_line[2048];
	known_hosts = libssh2_knownhost_init(session);
	if (libssh2_knownhost_addc(known_hosts, onion, "", keybuf, size, comment, strlen(comment), LIBSSH2_KNOWNHOST_TYPE_PLAIN|LIBSSH2_KNOWNHOST_KEYENC_RAW|LIBSSH2_KNOWNHOST_KEY_SSHRSA, NULL) != LIBSSH2_ERROR_NONE
	 || libssh2_knownhost_get(known_hosts, &cur_host, NULL) != LIBSSH2_ERROR_NONE
	 || libssh2_knownhost_writeline(known_hosts, cur_host, knownhost_line, sizeof(knownhost_line), &size, LIBSSH2_KNOWNHOST_FILE_OPENSSH) != LIBSSH2_ERROR_NONE)
	{
		fputs("Failed to get encoded known-hosts line\n", stderr);
		return EX_SOFTWARE;
	}
	libssh2_knownhost_free(known_hosts);
	libssh2_session_free(session);
	libssh2_exit();
	free(keybuf);

	FILE* const f = fopen(known_hosts_path, "a");
	if (!f)
	{
		perror("fopen(~/.ssh/known_hosts");
		return EX_CANTCREAT;
	}
	fwrite(knownhost_line, size, 1, f);
	fclose(f);
	free(known_hosts_path);

	return tunnel(dsthost, dstport);
}
