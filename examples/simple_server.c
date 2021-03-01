#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"

static quicly_context_t ctx;

int main(int argc, char **argv)
{
    //*** Init TLS related stuff. ***//
    ptls_openssl_sign_certificate_t sign_certificate;
    ptls_context_t tlsctx = {
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites,
    };

    ctx = quicly_spec_context;
    ctx.tls = &tlsctx;
    quicly_amend_ptls_context(ctx.tls);

    //*** Load TLS keys and certs. ***//
    int ret;
    if ((ret = ptls_load_certificates(&tlsctx, "cert.pem")) != 0) {
        fprintf(stderr, "failed to load certificates from file cert.pem: %d\n", ret);
        exit(1);
    }

    FILE *fp;
    if ((fp = fopen("key.pem", "r")) == NULL) {
        fprintf(stderr, "failed to open file key.pem: %s\n", strerror(errno));
        exit(1);
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (pkey == NULL) {
        fprintf(stderr, "failed to load private key from file: key.pem\n");
        exit(1);
    }
    ptls_openssl_init_sign_certificate(&sign_certificate, pkey);
    EVP_PKEY_free(pkey);
    tlsctx.sign_certificate = &sign_certificate.super;

    //*** Create addrinfo for socket binding ***//
    // quicly_stream_open_t stream_open = {on_stream_open};
    char *host = "127.0.0.1", *port = "4433";
    struct addrinfo hints, *sa;
    int fd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    if ((ret = getaddrinfo(host, port, &hints, &sa)) != 0 || sa == NULL) {
        fprintf(stderr, "failed to resolve address:%s:%s:%s\n", host, port,
                ret != 0 ? gai_strerror(ret) : "getaddrinfo returned NULL");
        return -1;
    }

    //*** Create and bind socket ***
    if ((fd = socket(sa->ai_family, SOCK_DGRAM, 0)) == -1) {
        perror("socket(2) failed");
        exit(1);
    }

    int reuseaddr = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
    if (bind(fd, sa->ai_addr, sa->ai_addrlen) != 0) {
        perror("bind(2) failed");
        exit(1);
    }

    //*** main loop ***//
    quicly_conn_t *conn = NULL;

    fd_set readfds;
    struct timeval tv;

    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    do {
        // initialize timeout delta
        tv.tv_sec = 1000;
        tv.tv_usec = 0;

        // if connection exits, retrieve timeout of the connection
        if (conn) {
            int64_t now = ctx.now->cb(ctx.now);
            int64_t timeout = quicly_get_first_timeout(conn);
            if (now < timeout) {
                int64_t delta = timeout - now;
                if (delta > 1000 * 1000)
                    delta = 1000 * 1000;
                tv.tv_sec = delta / 1000;
                tv.tv_usec = (delta % 1000) * 1000;
            }
        }

        // TODO: DO WE HAVE TO ZERO THE readfds EVERY TIME?
        // FD_ZERO(&readfds);
        // FD_SET(fd, &readfds);
    } while (select(fd + 1, &readfds, NULL, NULL, &tv) == -1 && errno == EINTR);
}