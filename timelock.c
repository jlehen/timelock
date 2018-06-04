#include <sys/time.h>
#include <err.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define AES128 1
#define CBC 1
#include "aes.h"

/* This contains the on-disk format version as well.*/
#define SIGNATURE   "Wait a bit! 1.0"       /* 16 bytes with final \0 */
#define BLOCKSIZE   16
#define TESTPERIOD  10                      /* seconds */
#define BLOCK_ALIGN(len)    (((len / BLOCKSIZE) + 1) * BLOCKSIZE)

struct __attribute__((__packed__)) header {
        char magic[16]; /* = SIGNATURE */
        uint64_t itercount;
        uint32_t msglen;
        uint32_t duration;
        char cipher[0];
};

const uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
const uint8_t key[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

const char *progname;
int stop;
uint64_t itercount;

static void
_usage(const char *error)
{
        if (error != NULL)
                fprintf(stderr, "Error: %s\n", error);
        fprintf(stderr,
                "\n"
                "Usage: %s seal <duration> <message> <outfile>\n"
                "       %s open <sealed_file>\n"
                "<duration> is expressed in seconds.\n",
                progname, progname);
        exit(1);
}

static void
_alarm()
{
        stop = 1;
}

static void
_info()
{
        printf("%lu iteration remaining...\n", itercount);
}

static void
_seal(unsigned long duration, const char *message, FILE *outfile)
{
        struct header hdr;
        uint8_t *buf;
        size_t msglen, bufsize;
        struct AES_ctx ctx;

        msglen = strlen(message);
        bufsize = BLOCK_ALIGN(msglen);

        buf = malloc((size_t)bufsize);
        if (buf == NULL)
                err(1, "malloc");

        if (signal(SIGALRM, &_alarm) == SIG_ERR)
                err(1, "signal");

        printf("Measuring decryption speed for %u seconds...\n", TESTPERIOD);
        /* Measure how many dercyption cycles we can do in one second. */
        stop = 0;
        itercount = 0;
        alarm(TESTPERIOD);
        while (!stop) {
                // Seems to be mangled by AES_CBC_decrypt_buffer().
                AES_init_ctx_iv(&ctx, key, iv);
                AES_CBC_decrypt_buffer(&ctx, buf, bufsize);
                itercount++;
        }
        itercount /= TESTPERIOD;

        printf("This computer can do about %lu decryptions per seconds "
                "of %lu blocks of 16 bytes.\n"
                "So we will encrypt %lu times to make it last %lu seconds "
                "to decrypt.\n",
                itercount, bufsize / BLOCKSIZE,
                itercount * duration, duration);
        itercount *= duration;

        strcpy(hdr.magic, SIGNATURE);
        hdr.itercount = itercount;
        hdr.msglen = msglen;
        hdr.duration = duration;

        bzero(buf, bufsize);
        memcpy(buf, message, msglen + 1);

        stop = 0;
        alarm(duration);
        while (itercount-- > 0) {
                // Seems to be mangled by AES_CBC_encrypt_buffer().
                AES_init_ctx_iv(&ctx, key, iv);
                AES_CBC_encrypt_buffer(&ctx, buf, bufsize);
        }

        /* XXX Check return value. */
        fwrite(&hdr, sizeof (hdr), 1, outfile);
        fwrite(buf, bufsize, 1, outfile);
}

static void
_open(FILE *infile)
{
        struct header hdr;
        uint8_t *buf;
        size_t bufsize;
        struct AES_ctx ctx;

        /* XXX Check return value. */
        fread(&hdr, sizeof (hdr), 1, infile);
        if (strcmp(hdr.magic, SIGNATURE) != 0)
                errx(2, "File doesn't have the right signature.");
        printf("Iteration count = %lu\n", hdr.itercount);
        printf("Message length = %u\n", hdr.msglen);
        printf("Originally requested duration = %u seconds\n", hdr.duration);

        bufsize = BLOCK_ALIGN(hdr.msglen);
        buf = malloc(bufsize);
        if (buf == NULL)
                err(1, "malloc");
        bzero(buf, bufsize);
        /* XXX Check return value. */
        fread(buf, bufsize, 1, infile);

        itercount = hdr.itercount;
        while (itercount-- > 0) {
                // Seems to be mangled by AES_CBC_decrypt_buffer().
                AES_init_ctx_iv(&ctx, key, iv);
                AES_CBC_decrypt_buffer(&ctx, buf, bufsize);
        }
        printf("Message:\n%s\n", (char *)buf);
}

int
main(int argc, char *argv[])
{
        char *message;
        unsigned long duration;
        FILE *file;

        progname = basename(argv[0]);
        if (argc < 2)
                _usage(NULL);

        if (signal(SIGINFO, &_info) == SIG_ERR)
                err(1, "signal");
        if (strcmp(argv[1], "seal") == 0) {
                if (argc < 5)
                        _usage("Missing arguments.");
                errno = 0;
                duration = strtoul(argv[2], NULL, 10);
                if ((duration == ULONG_MAX && errno == ERANGE) ||
                    (duration == 0 && errno == EINVAL))
                        err(1, "Invalid duration");
                message = argv[3];
                file = fopen(argv[4], "w+");
                if (file == NULL)
                        err(1, "Can't open \"%s\" for writing", argv[4]);
                _seal(duration, message, file);

        } else if (strcmp(argv[1], "open") == 0) {
                if (argc < 3)
                        _usage("Missing arguments.");
                file = fopen(argv[2], "r");
                if (file == NULL)
                        err(1, "Can't open \"%s\" for reading", argv[2]);
                _open(file);

        } else {
                warnx("Unknown command: %s", argv[1]);
                _usage(NULL);
        }

        exit(0);
}
