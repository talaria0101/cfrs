/* A SOCKS5 proxy, over TCP, for testing pod-netns's SOCKS5 connector.
 *
 * The SOCKS5 and HTTP CONNECT paths in pod-netns are unit-tested against
 * in-memory fakes, which prove the handshake is well formed but not that a flow
 * completes. This is the missing half: a real proxy that completes the
 * handshake, so `pod-netns --proxy <host:port> --socks5` can be run end to end.
 *
 * It does NOT relay to anything. It accepts the CONNECT, replies success, echoes
 * a fixed reply, and records what it was asked to connect to. That is exactly
 * what is needed to check two things at once: that the handshake completes, and
 * that the DESTINATION NAME reaches the proxy rather than a resolved address,
 * which is the property that lets a child with no working DNS reach a host by
 * name.
 *
 * Build: cc -O1 -o s5proxy s5proxy.c
 * Run:   ./s5proxy 1080
 * Then:  pod-netns --verbose --connect 127.0.0.1:PORT \
 *            --upstream some.name:443 --proxy 127.0.0.1:1080 --socks5 \
 *            -- testdata/relayer PORT
 *
 * MEASURED HERE, not assumed: run from this crate, `./s5proxy 1080` fails at
 * bind with EACCES, because bind is refused for a TCP port in this cage. So
 * neither this proxy nor the supervisor's dial to it can be exercised here, and
 * the SOCKS5 path stays unit-tested only. Running the proxy under
 * `pod-netns --listen` does not close the gap: the supervisor still has to dial
 * the proxy, and that dial is what is refused. On a host that permits bind, the
 * three commands above are the whole test.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void serve(int c)
{
	/* Greeting: VER NMETHODS METHODS... */
	unsigned char greet[2];
	if (recv(c, greet, 2, MSG_WAITALL) != 2)
		return;
	unsigned char methods = greet[1];
	unsigned char buf[512];
	if (recv(c, buf, methods, MSG_WAITALL) != methods)
		return;
	/* "no authentication required" */
	unsigned char sel[2] = { 0x05, 0x00 };
	send(c, sel, 2, 0);

	/* Request: VER CMD RSV ATYP ... */
	unsigned char head[4];
	if (recv(c, head, 4, MSG_WAITALL) != 4)
		return;
	char dest[256] = { 0 };
	unsigned port = 0;
	if (head[3] == 0x01) { /* IPv4 */
		unsigned char a[6];
		if (recv(c, a, 6, MSG_WAITALL) != 6)
			return;
		snprintf(dest, sizeof dest, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
		port = (unsigned)(a[4] << 8) | a[5];
	} else if (head[3] == 0x03) { /* DOMAINNAME */
		unsigned char l;
		if (recv(c, &l, 1, MSG_WAITALL) != 1)
			return;
		if (recv(c, buf, l, MSG_WAITALL) != l)
			return;
		memcpy(dest, buf, l);
		unsigned char p2[2];
		if (recv(c, p2, 2, MSG_WAITALL) != 2)
			return;
		port = (unsigned)(p2[0] << 8) | p2[1];
	} else if (head[3] == 0x04) { /* IPv6 */
		unsigned char a[18];
		if (recv(c, a, 18, MSG_WAITALL) != 18)
			return;
		snprintf(dest, sizeof dest, "<ipv6>");
		port = (unsigned)(a[16] << 8) | a[17];
	} else {
		printf("proxy: unknown ATYP %u\n", head[3]);
		return;
	}

	printf("proxy: CONNECT %s:%u cmd=%u\n", dest, port, head[1]);
	fflush(stdout);

	/* Succeeded: VER REP RSV ATYP BND.ADDR BND.PORT. BND.PORT is 0, which is
	 * what a proxy that does not relay should say about a port it did not
	 * bind. */
	unsigned char ok[10] = { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0 };
	send(c, ok, sizeof ok, 0);

	/* Then whatever the client sends, answer with a recognisable body. */
	char req[4096];
	ssize_t n = recv(c, req, sizeof req - 1, 0);
	if (n > 0) {
		req[n] = '\0';
		char *nl = strchr(req, '\n');
		if (nl)
			*nl = '\0';
		printf("proxy: tunnel received %zd bytes, first line: %s\n", n, req);
		fflush(stdout);
		/* The reply is the same shape the AF_UNIX test origin sends, so a client that
		 * checks for the HELLO token sees it. The length is taken from the
		 * string rather than written out: a hand-counted 58 truncates the
		 * token and the probe then fails for a reason that has nothing to do
		 * with pod-netns. */
		static const char reply[] =
			"HTTP/1.0 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO";
		send(c, reply, sizeof reply - 1, 0);
	}
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	int port = argc > 1 ? atoi(argv[1]) : 1080;

	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		printf("socket: %s\n", strerror(errno));
		return 1;
	}
	int one = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	struct sockaddr_in a;
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_port = htons((unsigned short)port);
	inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
	if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) {
		printf("bind: %s\n", strerror(errno));
		return 1;
	}
	if (listen(s, 4) < 0) {
		printf("listen: %s\n", strerror(errno));
		return 1;
	}
	printf("socks5 proxy listening on 127.0.0.1:%d\n", port);

	for (;;) {
		int c = accept(s, NULL, NULL);
		if (c < 0)
			break;
		serve(c);
		close(c);
	}
	return 0;
}