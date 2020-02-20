/*
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * @file
 * Haivision Open SRT (Secure Reliable Transport) protocol
 */

#include <srt/srt.h>

#include "libavutil/avassert.h"
#include "libavutil/collectd.h"
#include "libavutil/opt.h"
#include "libavutil/parseutils.h"
#include "libavutil/time.h"

#include "avformat.h"
#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "url.h"

/* This is for MPEG-TS and it's a default SRTO_PAYLOADSIZE for SRTT_LIVE (8 TS packets) */
#ifndef SRT_LIVE_DEFAULT_PAYLOAD_SIZE
#define SRT_LIVE_DEFAULT_PAYLOAD_SIZE 1316
#endif

/* This is the maximum payload size for Live mode, should you have a different payload type than MPEG-TS */
#ifndef SRT_LIVE_MAX_PAYLOAD_SIZE
#define SRT_LIVE_MAX_PAYLOAD_SIZE 1456
#endif

enum SRTMode {
    SRT_MODE_CALLER = 0,
    SRT_MODE_LISTENER = 1,
    SRT_MODE_RENDEZVOUS = 2
};

typedef struct SRTContext {
    const AVClass *class;
    int fd;
    int eid;
    int64_t rw_timeout;
    int64_t listen_timeout;
    int recv_buffer_size;
    int send_buffer_size;

    int64_t maxbw;
    int pbkeylen;
    char *passphrase;
#if SRT_VERSION_VALUE >= 0x010302
    int enforced_encryption;
    int kmrefreshrate;
    int kmpreannounce;
#endif
    int mss;
    int ffs;
    int ipttl;
    int iptos;
    int64_t inputbw;
    int oheadbw;
    int64_t latency;
    int tlpktdrop;
    int nakreport;
    int64_t connect_timeout;
    int payload_size;
    int64_t rcvlatency;
    int64_t peerlatency;
    enum SRTMode mode;
    int sndbuf;
    int rcvbuf;
    int lossmaxttl;
    int minversion;
    char *streamid;
    char *smoother;
    int messageapi;
    SRT_TRANSTYPE transtype;
    int linger;

    char *hostname;

    // Measurements via collectd
    char *collectd_address;
    int collectd_interval;
    char *collectd_identifier_host;
    char *collectd_identifier_plugin;
    char *collectd_identifier_plugin_instance;
    int collectd_debug;

    AVCollectdClient* collectd_client;
    lcc_identifier_t collectd_identifier;
    int64_t collectd_measurements_collected_at;
} SRTContext;

#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM
#define OFFSET(x) offsetof(SRTContext, x)
static const AVOption libsrt_options[] = {
    { "rw_timeout",     "Timeout of socket I/O operations",                                     OFFSET(rw_timeout),       AV_OPT_TYPE_INT64, { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "listen_timeout", "Connection awaiting timeout",                                          OFFSET(listen_timeout),   AV_OPT_TYPE_INT64, { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "send_buffer_size", "Socket send buffer size (in bytes)",                                 OFFSET(send_buffer_size), AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
    { "recv_buffer_size", "Socket receive buffer size (in bytes)",                              OFFSET(recv_buffer_size), AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
    { "pkt_size",       "Maximum SRT packet size",                                              OFFSET(payload_size),     AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, SRT_LIVE_MAX_PAYLOAD_SIZE, .flags = D|E, "payload_size" },
    { "payload_size",   "Maximum SRT packet size",                                              OFFSET(payload_size),     AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, SRT_LIVE_MAX_PAYLOAD_SIZE, .flags = D|E, "payload_size" },
    { "ts_size",        NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = SRT_LIVE_DEFAULT_PAYLOAD_SIZE }, INT_MIN, INT_MAX, .flags = D|E, "payload_size" },
    { "max_size",       NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = SRT_LIVE_MAX_PAYLOAD_SIZE },     INT_MIN, INT_MAX, .flags = D|E, "payload_size" },
    { "maxbw",          "Maximum bandwidth (bytes per second) that the connection can use",     OFFSET(maxbw),            AV_OPT_TYPE_INT64,    { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "pbkeylen",       "Crypto key len in bytes {16,24,32} Default: 16 (128-bit)",             OFFSET(pbkeylen),         AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, 32,        .flags = D|E },
    { "passphrase",     "Crypto PBKDF2 Passphrase size[0,10..64] 0:disable crypto",             OFFSET(passphrase),       AV_OPT_TYPE_STRING,   { .str = NULL },              .flags = D|E },
#if SRT_VERSION_VALUE >= 0x010302
    { "enforced_encryption", "Enforces that both connection parties have the same passphrase set",                              OFFSET(enforced_encryption), AV_OPT_TYPE_BOOL,  { .i64 = -1 }, -1, 1,         .flags = D|E },
    { "kmrefreshrate",       "The number of packets to be transmitted after which the encryption key is switched to a new key", OFFSET(kmrefreshrate),       AV_OPT_TYPE_INT,   { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
    { "kmpreannounce",       "The interval between when a new encryption key is sent and when switchover occurs",               OFFSET(kmpreannounce),       AV_OPT_TYPE_INT,   { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
#endif
    { "mss",            "The Maximum Segment Size",                                             OFFSET(mss),              AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, 1500,      .flags = D|E },
    { "ffs",            "Flight flag size (window size) (in bytes)",                            OFFSET(ffs),              AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
    { "ipttl",          "IP Time To Live",                                                      OFFSET(ipttl),            AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, 255,       .flags = D|E },
    { "iptos",          "IP Type of Service",                                                   OFFSET(iptos),            AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, 255,       .flags = D|E },
    { "inputbw",        "Estimated input stream rate",                                          OFFSET(inputbw),          AV_OPT_TYPE_INT64,    { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "oheadbw",        "MaxBW ceiling based on % over input stream rate",                      OFFSET(oheadbw),          AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, 100,       .flags = D|E },
    { "latency",        "receiver delay to absorb bursts of missed packet retransmissions",     OFFSET(latency),          AV_OPT_TYPE_INT64, { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "tsbpddelay",     "deprecated, same effect as latency option",                            OFFSET(latency),          AV_OPT_TYPE_INT64, { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "rcvlatency",     "receive latency",                                                      OFFSET(rcvlatency),       AV_OPT_TYPE_INT64, { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "peerlatency",    "peer latency",                                                         OFFSET(peerlatency),      AV_OPT_TYPE_INT64, { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "tlpktdrop",      "Enable receiver pkt drop",                                             OFFSET(tlpktdrop),        AV_OPT_TYPE_BOOL,     { .i64 = -1 }, -1, 1,         .flags = D|E },
    { "nakreport",      "Enable receiver to send periodic NAK reports",                         OFFSET(nakreport),        AV_OPT_TYPE_BOOL,     { .i64 = -1 }, -1, 1,         .flags = D|E },
    { "connect_timeout", "Connect timeout. Caller default: 3000, rendezvous (x 10)",            OFFSET(connect_timeout),  AV_OPT_TYPE_INT64, { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "mode",           "Connection mode (caller, listener, rendezvous)",                       OFFSET(mode),             AV_OPT_TYPE_INT,      { .i64 = SRT_MODE_CALLER }, SRT_MODE_CALLER, SRT_MODE_RENDEZVOUS, .flags = D|E, "mode" },
    { "caller",         NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = SRT_MODE_CALLER },     INT_MIN, INT_MAX, .flags = D|E, "mode" },
    { "listener",       NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = SRT_MODE_LISTENER },   INT_MIN, INT_MAX, .flags = D|E, "mode" },
    { "rendezvous",     NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = SRT_MODE_RENDEZVOUS }, INT_MIN, INT_MAX, .flags = D|E, "mode" },
    { "sndbuf",         "Send buffer size (in bytes)",                                          OFFSET(sndbuf),           AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
    { "rcvbuf",         "Receive buffer size (in bytes)",                                       OFFSET(rcvbuf),           AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
    { "lossmaxttl",     "Maximum possible packet reorder tolerance",                            OFFSET(lossmaxttl),       AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
    { "minversion",     "The minimum SRT version that is required from the peer",               OFFSET(minversion),       AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
    { "streamid",       "A string of up to 512 characters that an Initiator can pass to a Responder",  OFFSET(streamid),  AV_OPT_TYPE_STRING,   { .str = NULL },              .flags = D|E },
    { "smoother",       "The type of Smoother used for the transmission for that socket",       OFFSET(smoother),         AV_OPT_TYPE_STRING,   { .str = NULL },              .flags = D|E },
    { "messageapi",     "Enable message API",                                                   OFFSET(messageapi),       AV_OPT_TYPE_BOOL,     { .i64 = -1 }, -1, 1,         .flags = D|E },
    { "transtype",      "The transmission type for the socket",                                 OFFSET(transtype),        AV_OPT_TYPE_INT,      { .i64 = SRTT_INVALID }, SRTT_LIVE, SRTT_INVALID, .flags = D|E, "transtype" },
    { "live",           NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = SRTT_LIVE }, INT_MIN, INT_MAX, .flags = D|E, "transtype" },
    { "file",           NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = SRTT_FILE }, INT_MIN, INT_MAX, .flags = D|E, "transtype" },
    { "linger",         "Number of seconds that the socket waits for unsent data when closing", OFFSET(linger),           AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },

    { "collectd_address", "collectd server address or path to socket",                          OFFSET(collectd_address),                       AV_OPT_TYPE_STRING,      { .str = NULL }, .flags = D|E },
    { "collectd_identifier_host", "collectd identifier host",                                   OFFSET(collectd_identifier_host),               AV_OPT_TYPE_STRING,      { .str = NULL }, .flags = D|E },
    { "collectd_identifier_plugin", "collectd identifier plugin",                               OFFSET(collectd_identifier_plugin),             AV_OPT_TYPE_STRING,      { .str = "ffmpeg" }, .flags = D|E },
    { "collectd_identifier_plugin_instance", "collectd identifier plugin instance",             OFFSET(collectd_identifier_plugin_instance),    AV_OPT_TYPE_STRING,      { .str = "srt" }, .flags = D|E },
    { "collectd_interval", "collectd measurements interval (seconds)",                          OFFSET(collectd_interval),                      AV_OPT_TYPE_INT,         { .i64 = 5 }, 1, INT_MAX, .flags = D|E },
    { "collectd_debug", "log data sent to collectd",                                            OFFSET(collectd_debug),                         AV_OPT_TYPE_INT,         { .i64 = 0 }, 0, 1, .flags = D|E },
    { NULL }
};

typedef struct SRTStat {
    const char *name;
    int offset;
    enum AVOptionType type;
    const char *collectd_type;
} SRTStat;

static int libsrt_neterrno(URLContext *h)
{
    int err = srt_getlasterror(NULL);
    av_log(h, AV_LOG_ERROR, "%s\n", srt_getlasterror_str());
    if (err == SRT_EASYNCRCV)
        return AVERROR(EAGAIN);
    return AVERROR_UNKNOWN;
}

static int libsrt_socket_nonblock(int socket, int enable)
{
    int ret, blocking = enable ? 0 : 1;
    /* Setting SRTO_{SND,RCV}SYN options to 1 enable blocking mode, setting them to 0 enable non-blocking mode. */
    ret = srt_setsockopt(socket, 0, SRTO_SNDSYN, &blocking, sizeof(blocking));
    if (ret < 0)
        return ret;
    return srt_setsockopt(socket, 0, SRTO_RCVSYN, &blocking, sizeof(blocking));
}

static int libsrt_network_wait_fd(URLContext *h, int eid, int fd, int write)
{
    int ret, len = 1;
    int modes = write ? SRT_EPOLL_OUT : SRT_EPOLL_IN;
    SRTSOCKET ready[1];

    if (srt_epoll_add_usock(eid, fd, &modes) < 0)
        return libsrt_neterrno(h);
    if (write) {
        ret = srt_epoll_wait(eid, 0, 0, ready, &len, POLLING_TIME, 0, 0, 0, 0);
    } else {
        ret = srt_epoll_wait(eid, ready, &len, 0, 0, POLLING_TIME, 0, 0, 0, 0);
    }
    if (ret < 0) {
        if (srt_getlasterror(NULL) == SRT_ETIMEOUT)
            ret = AVERROR(EAGAIN);
        else
            ret = libsrt_neterrno(h);
    } else {
        ret = 0;
    }
    if (srt_epoll_remove_usock(eid, fd) < 0)
        return libsrt_neterrno(h);
    return ret;
}

/* TODO de-duplicate code from ff_network_wait_fd_timeout() */

static int libsrt_network_wait_fd_timeout(URLContext *h, int eid, int fd, int write, int64_t timeout, AVIOInterruptCB *int_cb)
{
    int ret;
    int64_t wait_start = 0;

    while (1) {
        if (ff_check_interrupt(int_cb))
            return AVERROR_EXIT;
        ret = libsrt_network_wait_fd(h, eid, fd, write);
        if (ret != AVERROR(EAGAIN))
            return ret;
        if (timeout > 0) {
            if (!wait_start)
                wait_start = av_gettime_relative();
            else if (av_gettime_relative() - wait_start > timeout)
                return AVERROR(ETIMEDOUT);
        }
    }
}

static int libsrt_listen(int eid, int fd, const struct sockaddr *addr, socklen_t addrlen, URLContext *h, int timeout)
{
    int ret;
    int reuse = 1;
    if (srt_setsockopt(fd, SOL_SOCKET, SRTO_REUSEADDR, &reuse, sizeof(reuse))) {
        av_log(h, AV_LOG_WARNING, "setsockopt(SRTO_REUSEADDR) failed\n");
    }
    ret = srt_bind(fd, addr, addrlen);
    if (ret)
        return libsrt_neterrno(h);

    ret = srt_listen(fd, 1);
    if (ret)
        return libsrt_neterrno(h);

    while ((ret = libsrt_network_wait_fd_timeout(h, eid, fd, 1, timeout, &h->interrupt_callback))) {
        switch (ret) {
        case AVERROR(ETIMEDOUT):
            continue;
        default:
            return ret;
        }
    }

    ret = srt_accept(fd, NULL, NULL);
    if (ret < 0)
        return libsrt_neterrno(h);
    if (libsrt_socket_nonblock(ret, 1) < 0)
        av_log(h, AV_LOG_DEBUG, "libsrt_socket_nonblock failed\n");

    return ret;
}

static int libsrt_listen_connect(int eid, int fd, const struct sockaddr *addr, socklen_t addrlen, int timeout, URLContext *h, int will_try_next)
{
    int ret;

    if (libsrt_socket_nonblock(fd, 1) < 0)
        av_log(h, AV_LOG_DEBUG, "ff_socket_nonblock failed\n");

    while ((ret = srt_connect(fd, addr, addrlen))) {
        ret = libsrt_neterrno(h);
        switch (ret) {
        case AVERROR(EINTR):
            if (ff_check_interrupt(&h->interrupt_callback))
                return AVERROR_EXIT;
            continue;
        case AVERROR(EINPROGRESS):
        case AVERROR(EAGAIN):
            ret = libsrt_network_wait_fd_timeout(h, eid, fd, 1, timeout, &h->interrupt_callback);
            if (ret < 0)
                return ret;
            ret = srt_getlasterror(NULL);
            srt_clearlasterror();
            if (ret != 0) {
                char buf[128];
                ret = AVERROR(ret);
                av_strerror(ret, buf, sizeof(buf));
                if (will_try_next)
                    av_log(h, AV_LOG_WARNING,
                           "Connection to %s failed (%s), trying next address\n",
                           h->filename, buf);
                else
                    av_log(h, AV_LOG_ERROR, "Connection to %s failed: %s\n",
                           h->filename, buf);
            }
        default:
            return ret;
        }
    }
    return ret;
}

static int libsrt_setsockopt(URLContext *h, int fd, SRT_SOCKOPT optname, const char * optnamestr, const void * optval, int optlen)
{
    if (srt_setsockopt(fd, 0, optname, optval, optlen) < 0) {
        av_log(h, AV_LOG_ERROR, "failed to set option %s on socket: %s\n", optnamestr, srt_getlasterror_str());
        return AVERROR(EIO);
    }
    return 0;
}

static int libsrt_getsockopt(URLContext *h, int fd, SRT_SOCKOPT optname, const char * optnamestr, void * optval, int * optlen)
{
    if (srt_getsockopt(fd, 0, optname, optval, optlen) < 0) {
        av_log(h, AV_LOG_ERROR, "failed to get option %s on socket: %s\n", optnamestr, srt_getlasterror_str());
        return AVERROR(EIO);
    }
    return 0;
}

/* - The "POST" options can be altered any time on a connected socket.
     They MAY have also some meaning when set prior to connecting; such
     option is SRTO_RCVSYN, which makes connect/accept call asynchronous.
     Because of that this option is treated special way in this app. */
static int libsrt_set_options_post(URLContext *h, int fd)
{
    SRTContext *s = h->priv_data;

    if ((s->inputbw >= 0 && libsrt_setsockopt(h, fd, SRTO_INPUTBW, "SRTO_INPUTBW", &s->inputbw, sizeof(s->inputbw)) < 0) ||
        (s->oheadbw >= 0 && libsrt_setsockopt(h, fd, SRTO_OHEADBW, "SRTO_OHEADBW", &s->oheadbw, sizeof(s->oheadbw)) < 0)) {
        return AVERROR(EIO);
    }
    return 0;
}

/* - The "PRE" options must be set prior to connecting and can't be altered
     on a connected socket, however if set on a listening socket, they are
     derived by accept-ed socket. */
static int libsrt_set_options_pre(URLContext *h, int fd)
{
    SRTContext *s = h->priv_data;
    int yes = 1;
    int latency = s->latency / 1000;
    int rcvlatency = s->rcvlatency / 1000;
    int peerlatency = s->peerlatency / 1000;
    int connect_timeout = s->connect_timeout;

    if ((s->mode == SRT_MODE_RENDEZVOUS && libsrt_setsockopt(h, fd, SRTO_RENDEZVOUS, "SRTO_RENDEZVOUS", &yes, sizeof(yes)) < 0) ||
        (s->transtype != SRTT_INVALID && libsrt_setsockopt(h, fd, SRTO_TRANSTYPE, "SRTO_TRANSTYPE", &s->transtype, sizeof(s->transtype)) < 0) ||
        (s->maxbw >= 0 && libsrt_setsockopt(h, fd, SRTO_MAXBW, "SRTO_MAXBW", &s->maxbw, sizeof(s->maxbw)) < 0) ||
        (s->pbkeylen >= 0 && libsrt_setsockopt(h, fd, SRTO_PBKEYLEN, "SRTO_PBKEYLEN", &s->pbkeylen, sizeof(s->pbkeylen)) < 0) ||
        (s->passphrase && libsrt_setsockopt(h, fd, SRTO_PASSPHRASE, "SRTO_PASSPHRASE", s->passphrase, strlen(s->passphrase)) < 0) ||
#if SRT_VERSION_VALUE >= 0x010302
        /* SRTO_STRICTENC == SRTO_ENFORCEDENCRYPTION (53), but for compatibility, we used SRTO_STRICTENC */
        (s->enforced_encryption >= 0 && libsrt_setsockopt(h, fd, SRTO_STRICTENC, "SRTO_STRICTENC", &s->enforced_encryption, sizeof(s->enforced_encryption)) < 0) ||
        (s->kmrefreshrate >= 0 && libsrt_setsockopt(h, fd, SRTO_KMREFRESHRATE, "SRTO_KMREFRESHRATE", &s->kmrefreshrate, sizeof(s->kmrefreshrate)) < 0) ||
        (s->kmpreannounce >= 0 && libsrt_setsockopt(h, fd, SRTO_KMPREANNOUNCE, "SRTO_KMPREANNOUNCE", &s->kmpreannounce, sizeof(s->kmpreannounce)) < 0) ||
#endif
        (s->mss >= 0 && libsrt_setsockopt(h, fd, SRTO_MSS, "SRTO_MSS", &s->mss, sizeof(s->mss)) < 0) ||
        (s->ffs >= 0 && libsrt_setsockopt(h, fd, SRTO_FC, "SRTO_FC", &s->ffs, sizeof(s->ffs)) < 0) ||
        (s->ipttl >= 0 && libsrt_setsockopt(h, fd, SRTO_IPTTL, "SRTO_IPTTL", &s->ipttl, sizeof(s->ipttl)) < 0) ||
        (s->iptos >= 0 && libsrt_setsockopt(h, fd, SRTO_IPTOS, "SRTO_IPTOS", &s->iptos, sizeof(s->iptos)) < 0) ||
        (s->latency >= 0 && libsrt_setsockopt(h, fd, SRTO_LATENCY, "SRTO_LATENCY", &latency, sizeof(latency)) < 0) ||
        (s->rcvlatency >= 0 && libsrt_setsockopt(h, fd, SRTO_RCVLATENCY, "SRTO_RCVLATENCY", &rcvlatency, sizeof(rcvlatency)) < 0) ||
        (s->peerlatency >= 0 && libsrt_setsockopt(h, fd, SRTO_PEERLATENCY, "SRTO_PEERLATENCY", &peerlatency, sizeof(peerlatency)) < 0) ||
        (s->tlpktdrop >= 0 && libsrt_setsockopt(h, fd, SRTO_TLPKTDROP, "SRTO_TLPKDROP", &s->tlpktdrop, sizeof(s->tlpktdrop)) < 0) ||
        (s->nakreport >= 0 && libsrt_setsockopt(h, fd, SRTO_NAKREPORT, "SRTO_NAKREPORT", &s->nakreport, sizeof(s->nakreport)) < 0) ||
        (connect_timeout >= 0 && libsrt_setsockopt(h, fd, SRTO_CONNTIMEO, "SRTO_CONNTIMEO", &connect_timeout, sizeof(connect_timeout)) <0 ) ||
        (s->sndbuf >= 0 && libsrt_setsockopt(h, fd, SRTO_SNDBUF, "SRTO_SNDBUF", &s->sndbuf, sizeof(s->sndbuf)) < 0) ||
        (s->rcvbuf >= 0 && libsrt_setsockopt(h, fd, SRTO_RCVBUF, "SRTO_RCVBUF", &s->rcvbuf, sizeof(s->rcvbuf)) < 0) ||
        (s->lossmaxttl >= 0 && libsrt_setsockopt(h, fd, SRTO_LOSSMAXTTL, "SRTO_LOSSMAXTTL", &s->lossmaxttl, sizeof(s->lossmaxttl)) < 0) ||
        (s->minversion >= 0 && libsrt_setsockopt(h, fd, SRTO_MINVERSION, "SRTO_MINVERSION", &s->minversion, sizeof(s->minversion)) < 0) ||
        (s->streamid && libsrt_setsockopt(h, fd, SRTO_STREAMID, "SRTO_STREAMID", s->streamid, strlen(s->streamid)) < 0) ||
        (s->smoother && libsrt_setsockopt(h, fd, SRTO_SMOOTHER, "SRTO_SMOOTHER", s->smoother, strlen(s->smoother)) < 0) ||
        (s->messageapi >= 0 && libsrt_setsockopt(h, fd, SRTO_MESSAGEAPI, "SRTO_MESSAGEAPI", &s->messageapi, sizeof(s->messageapi)) < 0) ||
        (s->payload_size >= 0 && libsrt_setsockopt(h, fd, SRTO_PAYLOADSIZE, "SRTO_PAYLOADSIZE", &s->payload_size, sizeof(s->payload_size)) < 0) ||
        ((h->flags & AVIO_FLAG_WRITE) && libsrt_setsockopt(h, fd, SRTO_SENDER, "SRTO_SENDER", &yes, sizeof(yes)) < 0)) {
        return AVERROR(EIO);
    }

    if (s->linger >= 0) {
        struct linger lin;
        lin.l_linger = s->linger;
        lin.l_onoff  = lin.l_linger > 0 ? 1 : 0;
        if (libsrt_setsockopt(h, fd, SRTO_LINGER, "SRTO_LINGER", &lin, sizeof(lin)) < 0)
            return AVERROR(EIO);
    }
    return 0;
}


static int libsrt_setup(URLContext *h, const char *uri, int flags)
{
    struct addrinfo hints = { 0 }, *ai, *cur_ai;
    int port, fd = -1;
    SRTContext *s = h->priv_data;
    const char *p;
    char buf[256];
    int ret;
    char hostname[1024],proto[1024],path[1024];
    char portstr[10];
    int open_timeout = 5000000;
    int eid;

    eid = srt_epoll_create();
    if (eid < 0)
        return libsrt_neterrno(h);
    s->eid = eid;

    av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname),
        &port, path, sizeof(path), uri);
    if (strcmp(proto, "srt"))
        return AVERROR(EINVAL);
    if (port <= 0 || port >= 65536) {
        av_log(h, AV_LOG_ERROR, "Port missing in uri\n");
        return AVERROR(EINVAL);
    }
    p = strchr(uri, '?');
    if (p) {
        if (av_find_info_tag(buf, sizeof(buf), "timeout", p)) {
            s->rw_timeout = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "listen_timeout", p)) {
            s->listen_timeout = strtol(buf, NULL, 10);
        }
    }
    if (s->rw_timeout >= 0) {
        open_timeout = h->rw_timeout = s->rw_timeout;
    }
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (s->mode == SRT_MODE_LISTENER)
        hints.ai_flags |= AI_PASSIVE;
    ret = getaddrinfo(hostname[0] ? hostname : NULL, portstr, &hints, &ai);
    if (ret) {
        av_log(h, AV_LOG_ERROR,
               "Failed to resolve hostname %s: %s\n",
               hostname, gai_strerror(ret));
        return AVERROR(EIO);
    }

    cur_ai = ai;

 restart:

    fd = srt_socket(cur_ai->ai_family, cur_ai->ai_socktype, 0);
    if (fd < 0) {
        ret = libsrt_neterrno(h);
        goto fail;
    }

    if ((ret = libsrt_set_options_pre(h, fd)) < 0) {
        goto fail;
    }

    /* Set the socket's send or receive buffer sizes, if specified.
       If unspecified or setting fails, system default is used. */
    if (s->recv_buffer_size > 0) {
        srt_setsockopt(fd, SOL_SOCKET, SRTO_UDP_RCVBUF, &s->recv_buffer_size, sizeof (s->recv_buffer_size));
    }
    if (s->send_buffer_size > 0) {
        srt_setsockopt(fd, SOL_SOCKET, SRTO_UDP_SNDBUF, &s->send_buffer_size, sizeof (s->send_buffer_size));
    }
    if (s->mode == SRT_MODE_LISTENER) {
        // multi-client
        if ((ret = libsrt_listen(s->eid, fd, cur_ai->ai_addr, cur_ai->ai_addrlen, h, open_timeout / 1000)) < 0)
            goto fail1;
        fd = ret;
    } else {
        if (s->mode == SRT_MODE_RENDEZVOUS) {
            ret = srt_bind(fd, cur_ai->ai_addr, cur_ai->ai_addrlen);
            if (ret)
                goto fail1;
        }

        if ((ret = libsrt_listen_connect(s->eid, fd, cur_ai->ai_addr, cur_ai->ai_addrlen,
                                          open_timeout / 1000, h, !!cur_ai->ai_next)) < 0) {
            if (ret == AVERROR_EXIT)
                goto fail1;
            else
                goto fail;
        }
    }
    if ((ret = libsrt_set_options_post(h, fd)) < 0) {
        goto fail;
    }

    if (flags & AVIO_FLAG_WRITE) {
        int packet_size = 0;
        int optlen = sizeof(packet_size);
        ret = libsrt_getsockopt(h, fd, SRTO_PAYLOADSIZE, "SRTO_PAYLOADSIZE", &packet_size, &optlen);
        if (ret < 0)
            goto fail1;
        if (packet_size > 0)
            h->max_packet_size = packet_size;
    }

    h->is_streamed = 1;
    s->fd = fd;

    freeaddrinfo(ai);
    return 0;

 fail:
    if (cur_ai->ai_next) {
        /* Retry with the next sockaddr */
        cur_ai = cur_ai->ai_next;
        if (fd >= 0)
            srt_close(fd);
        ret = 0;
        goto restart;
    }
 fail1:
    if (fd >= 0)
        srt_close(fd);
    freeaddrinfo(ai);
    return ret;
}

static void libsrt_gethostname(SRTContext *s) {
    size_t host_len = 1024;

    s->hostname = av_malloc(host_len);
    if (!s->hostname) {
        return;
    }

    gethostname(s->hostname, host_len);
}

static int libsrt_open(URLContext *h, const char *uri, int flags)
{
    SRTContext *s = h->priv_data;
    const char * p;
    char buf[256];
    int ret = 0;

    if (srt_startup() < 0) {
        return AVERROR_UNKNOWN;
    }

    if (s->collectd_address) {
        libsrt_gethostname(s);

        s->collectd_client = av_collectd_client_alloc(s, s->collectd_address);

        snprintf(s->collectd_identifier.host, sizeof(s->collectd_identifier.host), "%s", s->collectd_identifier_host ? s->collectd_identifier_host : s->hostname);
        snprintf(s->collectd_identifier.plugin, sizeof(s->collectd_identifier.plugin), "%s", s->collectd_identifier_plugin);
        snprintf(s->collectd_identifier.plugin_instance, sizeof(s->collectd_identifier.plugin_instance), "%s", s->collectd_identifier_plugin_instance);
    }

    /* SRT options (srt/srt.h) */
    p = strchr(uri, '?');
    if (p) {
        if (av_find_info_tag(buf, sizeof(buf), "maxbw", p)) {
            s->maxbw = strtoll(buf, NULL, 0);
        }
        if (av_find_info_tag(buf, sizeof(buf), "pbkeylen", p)) {
            s->pbkeylen = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "passphrase", p)) {
            av_freep(&s->passphrase);
            s->passphrase = av_strndup(buf, strlen(buf));
        }
#if SRT_VERSION_VALUE >= 0x010302
        if (av_find_info_tag(buf, sizeof(buf), "enforced_encryption", p)) {
            s->enforced_encryption = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "kmrefreshrate", p)) {
            s->kmrefreshrate = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "kmpreannounce", p)) {
            s->kmpreannounce = strtol(buf, NULL, 10);
        }
#endif
        if (av_find_info_tag(buf, sizeof(buf), "mss", p)) {
            s->mss = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "ffs", p)) {
            s->ffs = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "ipttl", p)) {
            s->ipttl = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "iptos", p)) {
            s->iptos = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "inputbw", p)) {
            s->inputbw = strtoll(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "oheadbw", p)) {
            s->oheadbw = strtoll(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "latency", p)) {
            s->latency = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "tsbpddelay", p)) {
            s->latency = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "rcvlatency", p)) {
            s->rcvlatency = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "peerlatency", p)) {
            s->peerlatency = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "tlpktdrop", p)) {
            s->tlpktdrop = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "nakreport", p)) {
            s->nakreport = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "connect_timeout", p)) {
            s->connect_timeout = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "payload_size", p) ||
            av_find_info_tag(buf, sizeof(buf), "pkt_size", p)) {
            s->payload_size = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "mode", p)) {
            if (!strcmp(buf, "caller")) {
                s->mode = SRT_MODE_CALLER;
            } else if (!strcmp(buf, "listener")) {
                s->mode = SRT_MODE_LISTENER;
            } else if (!strcmp(buf, "rendezvous")) {
                s->mode = SRT_MODE_RENDEZVOUS;
            } else {
                return AVERROR(EIO);
            }
        }
        if (av_find_info_tag(buf, sizeof(buf), "sndbuf", p)) {
            s->sndbuf = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "rcvbuf", p)) {
            s->rcvbuf = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "lossmaxttl", p)) {
            s->lossmaxttl = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "minversion", p)) {
            s->minversion = strtol(buf, NULL, 0);
        }
        if (av_find_info_tag(buf, sizeof(buf), "streamid", p)) {
            av_freep(&s->streamid);
            s->streamid = av_strdup(buf);
            if (!s->streamid) {
                ret = AVERROR(ENOMEM);
                goto err;
            }
        }
        if (av_find_info_tag(buf, sizeof(buf), "smoother", p)) {
            av_freep(&s->smoother);
            s->smoother = av_strdup(buf);
            if(!s->smoother) {
                ret = AVERROR(ENOMEM);
                goto err;
            }
        }
        if (av_find_info_tag(buf, sizeof(buf), "messageapi", p)) {
            s->messageapi = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "transtype", p)) {
            if (!strcmp(buf, "live")) {
                s->transtype = SRTT_LIVE;
            } else if (!strcmp(buf, "file")) {
                s->transtype = SRTT_FILE;
            } else {
                ret = AVERROR(EINVAL);
                goto err;
            }
        }
        if (av_find_info_tag(buf, sizeof(buf), "linger", p)) {
            s->linger = strtol(buf, NULL, 10);
        }
    }
    return libsrt_setup(h, uri, flags);
err:
    av_freep(&s->smoother);
    av_freep(&s->streamid);
    return ret;
}

static int libsrt_collectd_interval_elapsed(SRTContext *s) {
    if (s->collectd_measurements_collected_at == 0) {
        s->collectd_measurements_collected_at = av_gettime_relative();
        return 0;
    }

    int64_t now = av_gettime_relative();
    int64_t diff = (now - s->collectd_measurements_collected_at) * 1.0e-6;

    return diff > s->collectd_interval;
}

#define SRT_STATS_OFFSET(x) offsetof(SRT_TRACEBSTATS, x)

static const SRTStat libsrt_caller_interval_measurements[] = {
    { "pktSent",            SRT_STATS_OFFSET(pktSent),              AV_OPT_TYPE_INT64,  "packets" },
    { "pktSndLoss",         SRT_STATS_OFFSET(pktSndLoss),           AV_OPT_TYPE_INT,    "packets" },
    { "pktRetrans",         SRT_STATS_OFFSET(pktRetrans),           AV_OPT_TYPE_INT,    "packets" },
    { "pktSentACK",         SRT_STATS_OFFSET(pktSentACK),           AV_OPT_TYPE_INT,    "packets" },
    { "pktSentNAK",         SRT_STATS_OFFSET(pktSentNAK),           AV_OPT_TYPE_INT,    "packets" },
    { "pktSndFilterExtra",  SRT_STATS_OFFSET(pktSndFilterExtra),    AV_OPT_TYPE_INT,    "packets" },
    { "mbpsSendRate",       SRT_STATS_OFFSET(mbpsSendRate),         AV_OPT_TYPE_DOUBLE, "bitrate" },
    { "usSndDuration",      SRT_STATS_OFFSET(usSndDuration),        AV_OPT_TYPE_INT64,  "counter" },
    { "pktSndDrop",         SRT_STATS_OFFSET(pktSndDrop),           AV_OPT_TYPE_INT,    "packets" },
    { "byteSent",           SRT_STATS_OFFSET(byteSent),             AV_OPT_TYPE_UINT64, "bytes" },
    { "byteRetrans",        SRT_STATS_OFFSET(byteRetrans),          AV_OPT_TYPE_UINT64, "bytes" },
    { "byteSndDrop",        SRT_STATS_OFFSET(byteSndDrop),          AV_OPT_TYPE_UINT64, "bytes" },
    { NULL }
};

static const SRTStat libsrt_caller_instantaneous_measurements[] = {
    { "usPktSndPeriod",         SRT_STATS_OFFSET(usPktSndPeriod),       AV_OPT_TYPE_DOUBLE, "counter" },
    { "pktFlowWindow",          SRT_STATS_OFFSET(pktFlowWindow),        AV_OPT_TYPE_INT,    "packets" },
    { "pktCongestionWindow",    SRT_STATS_OFFSET(pktCongestionWindow),  AV_OPT_TYPE_INT,    "packets" },
    { "pktFlightSize",          SRT_STATS_OFFSET(pktFlightSize),        AV_OPT_TYPE_INT,    "packets" },
    { "msRTT",                  SRT_STATS_OFFSET(msRTT),                AV_OPT_TYPE_DOUBLE, "total_time_in_ms" },
    { "mbpsBandwidth",          SRT_STATS_OFFSET(mbpsBandwidth),        AV_OPT_TYPE_DOUBLE, "bitrate" },
    { "byteAvailSndBuf",        SRT_STATS_OFFSET(byteAvailSndBuf),      AV_OPT_TYPE_INT,    "bytes" },
    { "pktSndBuf",              SRT_STATS_OFFSET(pktSndBuf),            AV_OPT_TYPE_INT,    "packets" },
    { "byteSndBuf",             SRT_STATS_OFFSET(byteSndBuf),           AV_OPT_TYPE_INT,    "bytes" },
    { "msSndBuf",               SRT_STATS_OFFSET(msSndBuf),             AV_OPT_TYPE_INT,    "total_time_in_ms" },
    { NULL }
};

static const SRTStat libsrt_listener_interval_measurements[] = {
    { "pktRecv",                SRT_STATS_OFFSET(pktRecv),              AV_OPT_TYPE_INT64,  "packets" },
    { "pktRcvLoss",             SRT_STATS_OFFSET(pktRcvLoss),           AV_OPT_TYPE_INT,    "packets" },
    { "pktRecvACK",             SRT_STATS_OFFSET(pktRecvACK),           AV_OPT_TYPE_INT,    "packets" },
    { "pktRecvNAK",             SRT_STATS_OFFSET(pktRecvNAK),           AV_OPT_TYPE_INT,    "packets" },
    { "pktRcvFilterExtra",      SRT_STATS_OFFSET(pktRcvFilterExtra),    AV_OPT_TYPE_INT,    "packets" },
    { "pktRcvFilterSupply",     SRT_STATS_OFFSET(pktRcvFilterSupply),   AV_OPT_TYPE_INT,    "packets" },
    { "pktRcvFilterLoss",       SRT_STATS_OFFSET(pktRcvFilterLoss),     AV_OPT_TYPE_INT,    "packets" },
    { "mbpsRecvRate",           SRT_STATS_OFFSET(mbpsRecvRate),         AV_OPT_TYPE_DOUBLE, "bitrate" },
    { "pktReorderDistance",     SRT_STATS_OFFSET(pktReorderDistance),   AV_OPT_TYPE_INT,    "packets" },
    { "pktReorderTolerance",    SRT_STATS_OFFSET(pktReorderTolerance),  AV_OPT_TYPE_INT,    "packets" },
    { "pktRcvAvgBelatedTime",   SRT_STATS_OFFSET(pktRcvAvgBelatedTime), AV_OPT_TYPE_DOUBLE,  "count" },
    { "pktRcvBelated",          SRT_STATS_OFFSET(pktRcvBelated),        AV_OPT_TYPE_INT64,  "packets" },
    { "pktRcvDrop",             SRT_STATS_OFFSET(pktRcvDrop),           AV_OPT_TYPE_INT,    "packets" },
    { "pktRcvUndecrypt",        SRT_STATS_OFFSET(pktRcvUndecrypt),      AV_OPT_TYPE_INT,    "packets" },
    { "byteRecv",               SRT_STATS_OFFSET(byteRecv),             AV_OPT_TYPE_UINT64, "bytes" },
#ifdef SRT_ENABLE_LOSTBYTESCOUNT
    { "byteRcvLoss",            SRT_STATS_OFFSET(byteRcvLoss),          AV_OPT_TYPE_UINT64, "bytes" },
#endif
    { "byteRcvDrop",            SRT_STATS_OFFSET(byteRcvDrop),          AV_OPT_TYPE_UINT64, "bytes" },
    { "byteRcvUndecrypt",       SRT_STATS_OFFSET(byteRcvUndecrypt),     AV_OPT_TYPE_UINT64, "bytes" },
    { NULL }
};

static const SRTStat libsrt_listener_instantaneous_measurements[] = {
    { "msRTT",              SRT_STATS_OFFSET(msRTT),            AV_OPT_TYPE_DOUBLE, "total_time_in_ms" },
    { "byteAvailRcvBuf",    SRT_STATS_OFFSET(byteAvailRcvBuf),  AV_OPT_TYPE_INT,    "bytes" },
    { "pktRcvBuf",          SRT_STATS_OFFSET(pktRcvBuf),        AV_OPT_TYPE_INT,    "bytes" },
    { "byteRcvBuf",         SRT_STATS_OFFSET(byteRcvBuf),       AV_OPT_TYPE_INT,    "bytes" },
    { "msRcvBuf",           SRT_STATS_OFFSET(msRcvBuf),         AV_OPT_TYPE_INT,    "total_time_in_ms" },
    { "msRcvTsbPdDelay",    SRT_STATS_OFFSET(msRcvTsbPdDelay),  AV_OPT_TYPE_INT,    "total_time_in_ms" },
    { NULL }
};

static void libsrt_collectd_send_measurements(SRTContext *s, SRT_TRACEBSTATS *stats, const SRTStat *stat) {
    // Initialise value list
    lcc_value_list_t vals;
    vals.values_len = 1;
    vals.time = 0;
    vals.interval = s->collectd_interval;
    vals.identifier = s->collectd_identifier;

    // Initialise a single value type
    int values_types[1];
    vals.values_types = values_types;

    // Initialise a single value
    value_t values[1];
    vals.values = values;

    while (stat->name) {
        // Pointer to the value in stats struct
        uint8_t *val_ptr = ((uint8_t *)stats) + stat->offset;

        switch (stat->type)
        {
        case AV_OPT_TYPE_UINT64: {
            uint64_t* val = (uint64_t*) val_ptr;
            values_types[0] = LCC_TYPE_ABSOLUTE;
            values[0].absolute = *val;
            break;
        }
        case AV_OPT_TYPE_INT64: {
            int64_t *val = (int64_t *)val_ptr;
            values_types[0] = LCC_TYPE_ABSOLUTE;
            values[0].absolute = (uint64_t) *val;
            break;
        }
        case AV_OPT_TYPE_INT: {
            int *val = (int *)val_ptr;
            values_types[0] = LCC_TYPE_ABSOLUTE;
            values[0].absolute = (uint64_t) *val;
            break;
        }
        case AV_OPT_TYPE_DOUBLE: {
            double *val = (double *)val_ptr;
            values_types[0] = LCC_TYPE_GAUGE;
            values[0].gauge = *val;
            break;
        }
        }

        // Send stat to collectd
        snprintf(vals.identifier.type, sizeof(vals.identifier.type), "%s", stat->collectd_type);
        snprintf(vals.identifier.type_instance, sizeof(vals.identifier.type_instance), "%s", stat->name);
        av_collectd_putval(s->collectd_client, vals);

        if (s->collectd_debug) {
            av_collectd_print_value_list(s->collectd_client, vals);
        }

        stat++;
    }
}

/*
 * Collect all measurements from libsrt and send them to collectd
 * if the collection interval has elapsed.
 */
static void libsrt_collectd_measurements(SRTContext *s) {
    if (!s->collectd_client) {
        return;
    }

    if (!libsrt_collectd_interval_elapsed(s)) {
        return;
    }

    SRT_TRACEBSTATS stats = { 0 };
    s->collectd_measurements_collected_at = av_gettime_relative();

    // Interval measurements
    int ret = srt_bstats(s->fd, &stats, 1);
    if (ret < 0) {
        av_log(s, AV_LOG_WARNING, "failed to get interval measurements from libsrt\n");
        return;
    }

    if (s->mode == SRT_MODE_LISTENER) {
        libsrt_collectd_send_measurements(s, &stats, &libsrt_listener_interval_measurements[0]);
    } else if (s->mode == SRT_MODE_CALLER) {
        libsrt_collectd_send_measurements(s, &stats, &libsrt_caller_interval_measurements[0]);
    }

    // Instantaneous measurements
    ret = srt_bistats(s->fd, &stats, 1, 1);
    if (ret < 0) {
        av_log(s, AV_LOG_WARNING, "failed to get instantaneous measurements from libsrt\n");
        return;
    }

    if (s->mode == SRT_MODE_LISTENER) {
        libsrt_collectd_send_measurements(s, &stats, &libsrt_listener_instantaneous_measurements[0]);
    } else if (s->mode == SRT_MODE_CALLER) {
        libsrt_collectd_send_measurements(s, &stats, &libsrt_caller_instantaneous_measurements[0]);
    }
}

static int libsrt_read(URLContext *h, uint8_t *buf, int size)
{
    SRTContext *s = h->priv_data;
    int ret;

    libsrt_collectd_measurements(s);

    if (!(h->flags & AVIO_FLAG_NONBLOCK)) {
        ret = libsrt_network_wait_fd_timeout(h, s->eid, s->fd, 0, h->rw_timeout, &h->interrupt_callback);
        if (ret)
            return ret;
    }

    ret = srt_recvmsg(s->fd, buf, size);
    if (ret < 0) {
        ret = libsrt_neterrno(h);
    }

    return ret;
}

static int libsrt_write(URLContext *h, const uint8_t *buf, int size)
{
    SRTContext *s = h->priv_data;
    int ret;

    libsrt_collectd_measurements(s);

    if (!(h->flags & AVIO_FLAG_NONBLOCK)) {
        ret = libsrt_network_wait_fd_timeout(h, s->eid, s->fd, 1, h->rw_timeout, &h->interrupt_callback);
        if (ret)
            return ret;
    }

    ret = srt_sendmsg(s->fd, buf, size, -1, 0);
    if (ret < 0) {
        ret = libsrt_neterrno(h);
    }

    return ret;
}

static int libsrt_close(URLContext *h)
{
    SRTContext *s = h->priv_data;

    srt_close(s->fd);

    srt_epoll_release(s->eid);

    srt_cleanup();

    if (s->collectd_client) {
        av_collectd_client_free(&s->collectd_client);
    }

    av_freep(&s->hostname);

    return 0;
}

static int libsrt_get_file_handle(URLContext *h)
{
    SRTContext *s = h->priv_data;
    return s->fd;
}

static const AVClass libsrt_class = {
    .class_name = "libsrt",
    .item_name  = av_default_item_name,
    .option     = libsrt_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const URLProtocol ff_libsrt_protocol = {
    .name                = "srt",
    .url_open            = libsrt_open,
    .url_read            = libsrt_read,
    .url_write           = libsrt_write,
    .url_close           = libsrt_close,
    .url_get_file_handle = libsrt_get_file_handle,
    .priv_data_size      = sizeof(SRTContext),
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class     = &libsrt_class,
};
