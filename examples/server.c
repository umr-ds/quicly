/*
 * Copyright (c) 2019 Fastly, Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* required for glibc to use getaddrinfo, etc. */
#endif
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
#include <unistd.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"

/**
 * the QUIC context
 */
static quicly_context_t ctx;
/**
 * CID seed
 */
static quicly_cid_plaintext_t next_cid;

static int resolve_address(struct sockaddr *sa, socklen_t *salen, const char *host, const char *port, int family, int type,
                           int proto)
{
    struct addrinfo hints, *res;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = type;
    hints.ai_protocol = proto;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    if ((err = getaddrinfo(host, port, &hints, &res)) != 0 || res == NULL) {
        fprintf(stderr, "failed to resolve address:%s:%s:%s\n", host, port,
                err != 0 ? gai_strerror(err) : "getaddrinfo returned NULL");
        return -1;
    }

    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *salen = res->ai_addrlen;

    freeaddrinfo(res);
    return 0;
}

static void on_stop_sending(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received STOP_SENDING: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive_reset(quicly_stream_t *stream, int err)
{
    fprintf(stderr, "received RESET_STREAM: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return;

    /* obtain contiguous bytes from the receive buffer */
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

    if (quicly_sendstate_is_open(&stream->sendstate) && (input.len > 0)) {
        fwrite(input.base, 1, input.len, stdout);
        fflush(stdout);
        /* shutdown the stream after echoing all data */
        if (quicly_recvstate_transfer_complete(&stream->recvstate))
            quicly_streambuf_egress_shutdown(stream);
    }

    /* remove used bytes from receive buffer */
    quicly_streambuf_ingress_shift(stream, input.len);
}

static void process_msg(quicly_conn_t **conns, struct msghdr *msg, size_t dgram_len)
{
    size_t off = 0, i;

    /* split UDP datagram into multiple QUIC packets */
    while (off < dgram_len) {
        quicly_decoded_packet_t decoded;
        if (quicly_decode_packet(&ctx, &decoded, msg->msg_iov[0].iov_base, dgram_len, &off) == SIZE_MAX)
            return;
        /* find the corresponding connection (TODO handle version negotiation, rebinding, retry, etc.) */
        for (i = 0; conns[i] != NULL; ++i)
            if (quicly_is_destination(conns[i], NULL, msg->msg_name, &decoded))
                break;
        if (conns[i] != NULL) {
            /* let the current connection handle ingress packets */
            quicly_receive(conns[i], NULL, msg->msg_name, &decoded);
        } else {
            /* assume that the packet is a new connection */
            quicly_accept(conns + i, &ctx, NULL, msg->msg_name, &decoded, NULL, &next_cid, NULL);
        }
    }
}

static int send_one(int fd, struct sockaddr *dest, struct iovec *vec)
{
    struct msghdr mess = {.msg_name = dest, .msg_namelen = quicly_get_socklen(dest), .msg_iov = vec, .msg_iovlen = 1};
    int ret;

    while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
        ;
    return ret;
}

static int run_loop(int fd)
{
    quicly_conn_t *conns[256] = {0}; /* a null-terminated list of connections; proper app should use a hashmap or something */
    size_t i;

    while (1) {

        /* wait for sockets to become readable, or some event in the QUIC stack to fire */
        fd_set readfds;
        struct timeval tv;
        do {
            // extract the first timeout
            int64_t first_timeout = INT64_MAX, now = ctx.now->cb(ctx.now);
            for (i = 0; conns[i] != NULL; ++i) {
                int64_t conn_timeout = quicly_get_first_timeout(conns[i]);
                if (conn_timeout < first_timeout)
                    first_timeout = conn_timeout;
            }
            // compute difference between now and timeout
            if (now < first_timeout) {
                int64_t delta = first_timeout - now;
                if (delta > 1000 * 1000)
                    delta = 1000 * 1000;
                tv.tv_sec = delta / 1000;
                tv.tv_usec = (delta % 1000) * 1000;
            } else {
                tv.tv_sec = 1000;
                tv.tv_usec = 0;
            }
            
            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);

        } while (select(fd + 1, &readfds, NULL, NULL, &tv) == -1 && errno == EINTR);

        /* read the QUIC fd */
        if (FD_ISSET(fd, &readfds)) {
            uint8_t buf[4096];
            struct sockaddr_storage sa;
            struct iovec vec = {.iov_base = buf, .iov_len = sizeof(buf)};
            struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};
            ssize_t rret;
            while ((rret = recvmsg(fd, &msg, 0)) == -1 && errno == EINTR)
                ;
            if (rret > 0)
                process_msg(conns, &msg, rret);
        }

        /* send QUIC packets, if any */
        for (i = 0; conns[i] != NULL; ++i) {
            quicly_address_t dest, src;
            struct iovec dgrams[10];
            uint8_t dgrams_buf[PTLS_ELEMENTSOF(dgrams) * ctx.transport_params.max_udp_payload_size];
            size_t num_dgrams = PTLS_ELEMENTSOF(dgrams);
            int ret = quicly_send(conns[i], &dest, &src, dgrams, &num_dgrams, dgrams_buf, sizeof(dgrams_buf));
            switch (ret) {
            case 0: {
                size_t j;
                for (j = 0; j != num_dgrams; ++j) {
                    send_one(fd, &dest.sa, &dgrams[j]);
                }
            } break;
            case QUICLY_ERROR_FREE_CONNECTION:
                quicly_free(conns[i]);
                memmove(conns + i, conns + i + 1, sizeof(conns) - sizeof(conns[0]) * (i + 1));
                --i;
                break;
            default:
                fprintf(stderr, "quicly_send returned %d\n", ret);
                return 1;
            }
        }
    }

    return 0;
}

static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    static const quicly_stream_callbacks_t stream_callbacks = {
        quicly_streambuf_destroy, quicly_streambuf_egress_shift, quicly_streambuf_egress_emit, on_stop_sending, on_receive,
        on_receive_reset};
    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
        return ret;
    stream->callbacks = &stream_callbacks;
    return 0;
}

int main(int argc, char **argv)
{
    // ptls_openssl_sign_certificate_t sign_certificate;
    // ptls_context_t tlsctx = {
    //     .random_bytes = ptls_openssl_random_bytes,
    //     .get_time = &ptls_get_time,
    //     .key_exchanges = ptls_openssl_key_exchanges,
    //     .cipher_suites = ptls_openssl_cipher_suites,
    // };
    quicly_stream_open_t stream_open = {on_stream_open};
    char *host = "127.0.0.1", *port = "4433";
    struct sockaddr_storage sa;
    socklen_t salen;
    int fd;

    // /* setup quic context */
    // ctx = quicly_spec_context;
    // ctx.tls = &tlsctx;
    // quicly_amend_ptls_context(ctx.tls);
    // ctx.stream_open = &stream_open;

    // int ret;
    // if ((ret = ptls_load_certificates(&tlsctx, "cert.pem")) != 0) {
    //     fprintf(stderr, "failed to load certificates from file cert.pem: %d\n", ret);
    //     exit(1);
    // }

    // FILE *fp;
    // if ((fp = fopen("key.pem", "r")) == NULL) {
    //     fprintf(stderr, "failed to open file key.pem: %s\n", strerror(errno));
    //     exit(1);
    // }
    // EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    // fclose(fp);
    // if (pkey == NULL) {
    //     fprintf(stderr, "failed to load private key from file: key.pem\n");
    //     exit(1);
    // }
    // ptls_openssl_init_sign_certificate(&sign_certificate, pkey);
    // EVP_PKEY_free(pkey);
    // tlsctx.sign_certificate = &sign_certificate.super;

    if (resolve_address((struct sockaddr *)&sa, &salen, host, port, AF_INET, SOCK_DGRAM, 0) != 0)
        exit(1);

    if ((fd = socket(sa.ss_family, SOCK_DGRAM, 0)) == -1) {
        perror("socket(2) failed");
        exit(1);
    }

    int reuseaddr = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
    if (bind(fd, (struct sockaddr *)&sa, salen) != 0) {
        perror("bind(2) failed");
        exit(1);
    }

    return run_loop(fd);
}
