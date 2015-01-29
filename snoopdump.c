/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2015, Joyent, Inc.
 */

/*
 * snoopdump.c: very basic snoop file analyzer.  See RFC 1761.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef int64_t off64_t;
typedef unsigned int uint_t;

static const char *sd_arg0;
static int sd_gotsig = 0;

static void sd_usage(void);
static void sd_sig(int, siginfo_t *, void *);
static int sd_snoopdump(int);

#define	TIMESTAMP_BUFSZ		(sizeof ("2015-01-01T00:00:00.000Z"))

int
main(int argc, char *argv[])
{
	int fd, err;

	sd_arg0 = argv[0];

	if (argc > 2) {
		sd_usage();
	}

	/*
	 * Add handlers for SIGUSR1 and SIGINFO (typically sent by CTRL-\) that
	 * print progress reading the file.
	 */
	struct sigaction sa;
	bzero(&sa, sizeof (sa));
	sa.sa_flags |= SA_RESTART;
	sa.sa_sigaction = sd_sig;
	if (sigaction(SIGUSR1, &sa, NULL) != 0) {
		perror("sigaction");
		(void) fprintf(stderr, "SIGUSR1 support is disabled.");
	}
	if (sigaction(SIGINFO, &sa, NULL) != 0) {
		perror("sigaction");
		(void) fprintf(stderr, "SIGINFO support is disabled.");
	}

	if (argc == 2) {
		fd = open(argv[1], O_RDONLY);
		if (fd < 0) {
			perror("open");
			exit(EXIT_FAILURE);
		}
	} else {
		fd = STDIN_FILENO;
	}

	err = sd_snoopdump(fd);
	(void) close(fd);

	if (err != 0) {
		(void) fprintf(stderr, "%s: bailing out after errors\n",
		    sd_arg0);
		return (-1);
	}

	return (0);
}

static void
sd_usage(void)
{
	(void) fprintf(stderr, "usage: %s snoopfile\n", sd_arg0);
	exit(2);
}

static void
sd_sig(int signum, siginfo_t *info __attribute__((unused)),
    void *uap __attribute__((unused)))
{
	assert(signum == SIGUSR1 || signum == SIGINFO);
	sd_gotsig = 1;
};

/*
 * Flags for a snoopdump operation.
 */
typedef enum {
	SD_F_DONE		= 0x1,	/* finished processing all input */
	SD_F_WARNED_FUTURE	= 0x2,	/* already warned about future pkts */
} sd_flags_t;

/*
 * Flags for sd_progress().
 */
typedef enum {
	SD_PROGRESS_NORMAL = 0x0,	/* normal progress check */
	SD_PROGRESS_FORCE = 0x1,	/* force progress output */
} sd_progress_flags_t;

/*
 * These structures are defined by RFC 1761.
 */
#pragma pack(0)
/*
 * File format header.
 */
typedef struct {
	char		sh_magic[8];
	uint32_t	sh_version;
	uint32_t	sh_datalink_type;
} snoop_header_t;

/*
 * Packet record header.
 */
typedef struct {
	uint32_t	shp_pktlen_full;	/* original packet length */
	uint32_t	shp_pktlen;		/* saved packet length */
	uint32_t	shp_pktreclen;		/* total record length */
	uint32_t	shp_ndrops_cumulative;	/* cumulative drops */
	uint32_t	shp_time_sec;		/* timestamp */
	uint32_t	shp_time_usec;		/* microsecond timestamp */
} snoop_packet_header_t;
#pragma pack()

/*
 * Stores all the state for a given snoopdump operation.
 */
typedef struct {
	int		sd_fd;			/* input fd */
	FILE		*sd_input;		/* input stream */
	sd_flags_t	sd_flags;		/* operation flags */
	time_t		sd_start;		/* start time */
	off64_t		sd_nbytesproc;		/* bytes processed */
	off64_t		sd_ntotbytes;		/* total bytes in input */
	uint_t		sd_npacketsread;	/* packets read so far */
	uint_t		sd_nwarnings;		/* non-fatal errors */
	uint_t		sd_nerrors;		/* fatal errors */
	uint_t		sd_ndrops;		/* total drops */
	snoop_packet_header_t sd_lastpacket;	/* last packet read */
} snoopdump_t;

static void sd_progress(snoopdump_t *, sd_progress_flags_t);
static int sd_read_header(snoopdump_t *);
static int sd_read_packet(snoopdump_t *);
static int sd_packet_check(snoopdump_t *, snoop_packet_header_t *, size_t);
static void sd_packet_dump(snoopdump_t *, snoop_packet_header_t *);
static void sd_packet_time(snoopdump_t *, snoop_packet_header_t *, char *,
    size_t);

/*
 * Read the snoop file from the given file descriptor and dump out basic
 * information about it.  If this were library-ized, this would be the main
 * public entry point.  This implementation basically assumes that it's not
 * running as a library because of the way it dumps to stdout and stderr.
 * Everything else should be safe for dropping into a library context.
 */
static int
sd_snoopdump(int fd)
{
	int err, dupfd, rv;
	struct stat st;
	snoopdump_t *sdp;

	/*
	 * fclose(3C) will close(2) the fd that we passed to fdopen(3C), but the
	 * caller still owns "fd", so we dup() it for ourselves here.
	 */
	dupfd = dup(fd);
	if (dupfd < 0) {
		perror("dup");
		return (-1);
	}

	rv = -1;
	sdp = malloc(sizeof (*sdp));
	if (sdp == NULL) {
		perror("malloc");
		return (-1);
	}

	bzero(sdp, sizeof (*sdp));
	sdp->sd_fd = dupfd;
	sdp->sd_input = fdopen(dupfd, "r");
	if (sdp->sd_input == NULL) {
		(void) close(dupfd);
		perror("fdopen");
		goto out;
	}

	(void) time(&sdp->sd_start);
	err = fstat(fd, &st);
	if (err != 0 || !S_ISREG(st.st_mode)) {
		if (err != 0)
			perror("fstat");

		(void) fprintf(stderr, "warn: total input size is not known\n");
	} else {
		sdp->sd_ntotbytes = st.st_size;
	}

	if (sd_read_header(sdp) != 0)
		return (-1);

	for (;;) {
		sd_progress(sdp, SD_PROGRESS_NORMAL);
		if (sd_read_packet(sdp) != 0)
			return (-1);

		if ((sdp->sd_flags & SD_F_DONE) != 0)
			break;
	}

	rv = 0;
	sd_progress(sdp, SD_PROGRESS_FORCE);
	(void) printf("%d total drops\n", sdp->sd_ndrops);

	if (sdp->sd_npacketsread > 0) {
		char timebuf[TIMESTAMP_BUFSZ];

		sd_packet_time(sdp, &sdp->sd_lastpacket, timebuf,
		    sizeof (timebuf));
		(void) printf("packet %u: %s\n", sdp->sd_npacketsread,
		    timebuf);
	}

out:
	if (sdp->sd_input != NULL)
		(void) fclose(sdp->sd_input);
	free(sdp);
	return (rv);
}

/*
 * Check whether we've been asked to report progress (using the sd_gotsig flag,
 * set by the signal handler), and report progress if so.  If SD_PROGRESS_FORCE
 * is set, then always print progress.
 */
static void
sd_progress(snoopdump_t *sdp, sd_progress_flags_t flags)
{
	if (sd_gotsig || (flags & SD_PROGRESS_FORCE) != 0) {
		(void) fprintf(stderr, "%s: found %d packets in %lld",
		    sd_arg0, sdp->sd_npacketsread, sdp->sd_nbytesproc);
		if (sdp->sd_ntotbytes != 0)
			(void) fprintf(stderr, " of %lld total bytes "
			    "(%lld%%)\n", sdp->sd_ntotbytes,
			    100 * sdp->sd_nbytesproc / sdp->sd_ntotbytes);
		else
			(void) fprintf(stderr, " bytes\n");
		sd_gotsig = 0;
	}
}

/*
 * Read the snoop file header.  Returns non-zero on fatal error.
 */
static int
sd_read_header(snoopdump_t *sdp)
{
	snoop_header_t sh;
	snoop_header_t *shp;
	char expected_magic[] = { 's', 'n', 'o', 'o', 'p', '\0', '\0', '\0' };

	shp = &sh;
	if (fread(shp, sizeof (*shp), 1, sdp->sd_input) != 1) {
		(void) fprintf(stderr, "error: failed to read input "
		    "header: %s\n", feof(sdp->sd_input) ? "file too short" :
		    "read error");
		return (-1);
	}

	if (bcmp(&shp->sh_magic[0], &expected_magic[0],
	    sizeof (expected_magic)) != 0) {
		(void) fprintf(stderr, "error: input header has bad magic\n");
		return (-1);
	}

	shp->sh_version = ntohl(shp->sh_version);
	shp->sh_datalink_type = ntohl(shp->sh_datalink_type);

	if (shp->sh_version != 2) {
		(void) fprintf(stderr, "error: unknown snoop version: %d\n",
		    shp->sh_version);
		return (-1);
	}

	(void) printf("datalink type: %d\n", shp->sh_datalink_type);
	sdp->sd_nbytesproc += sizeof (*shp);
	return (0);
}

/*
 * Read a single packet from the snoop file.  Returns non-zero on fatal error.
 */
static int
sd_read_packet(snoopdump_t *sdp)
{
	snoop_packet_header_t *spp;
	size_t maxpktsize = 16 * 1024;
	size_t bufsz;
	char *buf;
	char timebuf[TIMESTAMP_BUFSZ];

	/*
	 * Read the packet from the stream and adjust the endianness of the
	 * contained integers.
	 */
	spp = &sdp->sd_lastpacket;
	if (fread(spp, sizeof (*spp), 1, sdp->sd_input) != 1) {
		if (feof(sdp->sd_input)) {
			sdp->sd_flags |= SD_F_DONE;
			return (0);
		}

		(void) fprintf(stderr, "error: failed to read packet\n");
		return (-1);
	}

	sdp->sd_npacketsread++;
	spp->shp_pktlen_full = ntohl(spp->shp_pktlen_full);
	spp->shp_pktlen = ntohl(spp->shp_pktlen);
	spp->shp_pktreclen = ntohl(spp->shp_pktreclen);
	spp->shp_ndrops_cumulative = ntohl(spp->shp_ndrops_cumulative);
	spp->shp_time_sec = ntohl(spp->shp_time_sec);
	spp->shp_time_usec = ntohl(spp->shp_time_usec);

	/*
	 * Check whether the packet looks sane.  If not, we'll consider that a
	 * fatal error and bail out, since we don't know where the next packet
	 * starts if this packet header is invalid.
	 */
	if (sd_packet_check(sdp, spp, maxpktsize) != 0)
		return (-1);

	/*
	 * Issue warnings for irregularities that don't necessarily indicate
	 * that the header is totally invalid.
	 */
	if ((sdp->sd_flags & SD_F_WARNED_FUTURE) == 0 &&
	    spp->shp_time_sec > sdp->sd_start) {
		(void) fprintf(stderr, "warn: packet %d (file offset %jd) "
		    "is from the future\n", sdp->sd_npacketsread,
		    (intmax_t)sdp->sd_nbytesproc);
		sdp->sd_flags |= SD_F_WARNED_FUTURE;
		sdp->sd_nwarnings++;
	}

	/*
	 * Skip over the contents of the packet record, which may be larger than
	 * the packet data.  (Again, see the RFC.)  The assertion is safe, and
	 * the buffer size is reasonable, because the buffer size condition was
	 * checked by sd_packet_check().  If it's larger than we can reasonably
	 * support on the stack, we consider that a fatal error.  This isn't
	 * likely in practice.
	 */
	bufsz = spp->shp_pktreclen - sizeof (*spp);
	assert(bufsz <= maxpktsize);
	buf = alloca(bufsz);
	if (fread(buf, bufsz, 1, sdp->sd_input) != 1) {
		sdp->sd_nerrors++;

		if (feof(sdp->sd_input)) {
			(void) fprintf(stderr,
			    "error: packet %u (file offset %llu): "
			    "unexpected EOF\n", sdp->sd_npacketsread,
			    (uint64_t)sdp->sd_nbytesproc);
		} else {
			(void) fprintf(stderr,
			    "error: packet %u (file offset %llu): "
			    "read error\n", sdp->sd_npacketsread,
			    (uint64_t)sdp->sd_nbytesproc);
		}

		return (-1);
	}

	/*
	 * If we're going to print anything for this packet, do it now.  That
	 * means printing out the timestamp of the first packet, and details
	 * about any packets that were preceded by some number of dropped
	 * packets.
	 */
	if (sdp->sd_npacketsread == 1) {
		sd_packet_time(sdp, spp, timebuf, sizeof (timebuf));
		(void) fprintf(stderr, "packet 1: %s\n", timebuf);
	}

	if (spp->shp_ndrops_cumulative > sdp->sd_ndrops) {
		sd_packet_time(sdp, spp, timebuf, sizeof (timebuf));
		(void) fprintf(stderr, "warning: packet %u (time %s): "
		    "%u drops\n", sdp->sd_npacketsread, timebuf,
		    spp->shp_ndrops_cumulative - sdp->sd_ndrops);
	}

	/*
	 * Update operation state.
	 */
	sdp->sd_nbytesproc += spp->shp_pktreclen;
	sdp->sd_ndrops = spp->shp_ndrops_cumulative;
	return (0);
}

/*
 * Check the packet header for general sanity.  Some of these checks are
 * heuristic, but they're intended to be conservative, bailing out when anything
 * looks suspicious.
 */
static int
sd_packet_check(snoopdump_t *sdp, snoop_packet_header_t *spp, size_t maxpktsize)
{
	const char *reason = NULL;

	if (spp->shp_pktlen > spp->shp_pktlen_full) {
		reason = "included length exceeds original length";
	} else if (spp->shp_pktreclen < spp->shp_pktlen) {
		reason = "packet record length exceeds included length";
	} else if (spp->shp_time_usec >= 1000000) {
		reason = "packet microsecond timestamp is invalid";
	} else if (abs(spp->shp_time_sec - sdp->sd_start) > 86400 * 365 * 10) {
		/*
		 * We use a range of 10 years around the current time to
		 * try to identify wildly ridiculous timestamps, which probably
		 * indicate that the file is corrupt or we've read it
		 * incorrectly.
		 */
		reason = "packet timestamp seems invalid";
	} else if (spp->shp_pktreclen > maxpktsize) {
		reason = "packet data length is unsupported (too large)";
	} else if (spp->shp_ndrops_cumulative < sdp->sd_ndrops) {
		reason = "packet has invalid number of drops";
	}

	if (reason == NULL)
		return (0);

	(void) fprintf(stderr, "error: packet %d (file offset %jd): %s\n",
	    sdp->sd_npacketsread, (intmax_t)sdp->sd_nbytesproc, reason);
	sdp->sd_nerrors++;
	sd_packet_dump(sdp, spp);
	return (-1);
}

/*
 * Dump the details of a packet record (not including packet contents).
 */
static void
sd_packet_dump(snoopdump_t *sdp __attribute__((unused)),
    snoop_packet_header_t *spp)
{
	(void) fprintf(stderr, "%-30s = %d\n",
	    "original packet length", spp->shp_pktlen_full);
	(void) fprintf(stderr, "%-30s = %d\n",
	    "captured packet length", spp->shp_pktlen);
	(void) fprintf(stderr, "%-30s = %d\n",
	    "packet record length", spp->shp_pktreclen);
	(void) fprintf(stderr, "%-30s = %d\n",
	    "cumulative drops", spp->shp_ndrops_cumulative);
	(void) fprintf(stderr, "%-30s = %d\n",
	    "time in seconds", spp->shp_time_sec);
	(void) fprintf(stderr, "%-30s = %d\n",
	    "time in microseconds", spp->shp_time_usec);
}

/*
 * Save into "buf" an ISO 8601 UTC timestamp with microsecond precision
 * corresponding to the timestamp of the packet.  Example output would be
 * "2015-01-01T00:00:00.123456Z".  "buf" is a buffer of length "bufsz", which
 * should be (but doesn't have to be) at least TIMESTAMP_BUFSZ bytes long.
 */
static void
sd_packet_time(snoopdump_t *sdp __attribute__((unused)),
    snoop_packet_header_t *spp, char *buf, size_t bufsz)
{
	struct tm timeinfo;
	time_t timestamp;
	char timebuf[TIMESTAMP_BUFSZ];

	timestamp = (time_t)spp->shp_time_sec;
	(void) gmtime_r(&timestamp, &timeinfo);
	if (strftime(timebuf, sizeof (timebuf), "%FT%T", &timeinfo) == 0)
		/* Should be impossible. */
		abort();

	(void) snprintf(buf, bufsz, "%s.%06dZ", timebuf, spp->shp_time_usec);
}
