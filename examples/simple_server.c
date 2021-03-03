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

#include <execinfo.h>
#include <signal.h>

extern void convert_error(quicly_stream_t *stream, int err);

static quicly_context_t ctx;
static quicly_cid_plaintext_t next_cid;

static void on_error(quicly_stream_t *stream, int err) {
    fprintf(stderr, "received error: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive(quicly_stream_t *stream, size_t offset, const void *src, size_t len) {
    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, offset, src, len) != 0) {
        puts("No data in stream\n");
        return;
    }

    puts("Starting callback\n");

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    /* server: echo back to the client */
    fwrite(input.base, 1, input.len, stdout);
    fflush(stdout);
    
    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);
}

static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    static const quicly_stream_callbacks_t stream_callbacks = {
        quicly_streambuf_destroy,
        quicly_streambuf_egress_shift,
        quicly_streambuf_egress_emit,
        on_error,
        on_receive,
        on_error
        };
    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
        return ret;
    stream->callbacks = &stream_callbacks;
    return 0;
}

void handler(int sig) {
  void *array[10];
  size_t size;

  // get void*'s for all entries on the stack
  size = backtrace(array, 10);

  // print out all the frames to stderr
  fprintf(stderr, "Error: signal %d:\n", sig);
  backtrace_symbols_fd(array, size, STDERR_FILENO);
  exit(1);
}

int main(int argc, char **argv)
{
    signal(SIGABRT, handler);

    //*** Init TLS related stuff. ***//
    ptls_openssl_sign_certificate_t sign_certificate;
    ptls_context_t tlsctx = {
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites,
    };

    quicly_stream_open_t stream_open = {on_stream_open};
    ctx = quicly_spec_context;
    ctx.tls = &tlsctx;
    quicly_amend_ptls_context(ctx.tls);
    ctx.stream_open = &stream_open;

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
    puts("Entering main loop");
    quicly_conn_t *conn = NULL;

    while (1) {
        fd_set readfds;
        struct timeval tv;

        do {
            puts("select loop");
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

            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);
        } while (select(fd + 1, &readfds, NULL, NULL, &tv) == -1 && errno == EINTR);

        // socket is in readfds -> socket is ready to read
        if (FD_ISSET(fd, &readfds)) {
            puts("reading from socket");
            uint8_t buf[4096];
            struct sockaddr src_addr;
            socklen_t addrlen;

            ssize_t rret = recvfrom(fd, buf, sizeof(buf), 0, &src_addr, &addrlen);
            if (rret > 0) {
                printf("read %zu bytes from socket\n", rret);
                size_t offset = 0;

                while (offset < rret) {
                    quicly_decoded_packet_t decoded;
                    // try to decode the packet (if SIZE_MAX returned, there was no packet)
                    if (quicly_decode_packet(&ctx, &decoded, buf, rret, &offset) == SIZE_MAX)
                        break;

                    if (conn) {
                        if (quicly_is_destination(conn, NULL, &src_addr, &decoded)) {
                            quicly_receive(conn, NULL, &src_addr, &decoded);
                            puts("received packet");
                        }
                    } else {
                        quicly_accept(&conn, &ctx, NULL, &src_addr, &decoded, NULL, &next_cid, NULL);
                        puts("accepted connection");
                    }
                }
            }
        }

        // allow quic to send
        if (conn) {
            printf("Connection is not null. Sending packets.\n");
            quicly_address_t dest, src;
            struct iovec dgram;
            uint8_t dgram_buf[ctx.transport_params.max_udp_payload_size];
            size_t num_dgrams = 1;
            puts("quicly send");
            int ret = quicly_send(conn, &dest, &src, &dgram, &num_dgrams, dgram_buf, sizeof(dgram_buf));
            // switch (ret) {
            //     case 0: {
            //         puts("sendto");
            //         ssize_t rret = sendto(fd, dgram.iov_base, dgram.iov_len, 0, &dest.sa, dest.sa.sa_len);
            //         printf("sent %zu bytes: %zu\n", dgram.iov_len, rret);
            //         }
            //         break;
            //     case QUICLY_ERROR_FREE_CONNECTION:
            //         /* connection has been closed and free */
            //         quicly_free(conn);
            //         conn = NULL;
            //         break;
            //     default:
            //         fprintf(stderr, "quicly_send returned %d\n", ret);
            //         break;
            // }
        }

        puts("loop");
    }
}
