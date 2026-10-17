/*
 * Host-side unit tests for android/app/src/main/cpp/aura_sni_firewall.c.
 *
 * Build and run (Linux/macOS):
 *   cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
 *      -I android/app/src/main/cpp \
 *      android/app/src/main/cpp/aura_sni_firewall.c \
 *      test/native/test_aura_sni_firewall.c -o /tmp/aura_sni_test -lpthread
 *   /tmp/aura_sni_test
 */
#include "aura_sni_firewall.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        checks++;                                                              \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            fprintf (stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);     \
        }                                                                      \
    } while (0)

typedef struct
{
    uint8_t data[70000];
    size_t len;
} Buf;

static void
put8 (Buf *b, uint8_t v)
{
    b->data[b->len++] = v;
}

static void
put16 (Buf *b, uint16_t v)
{
    put8 (b, (uint8_t)(v >> 8));
    put8 (b, (uint8_t)v);
}

static void
put_bytes (Buf *b, const void *p, size_t n)
{
    memcpy (b->data + b->len, p, n);
    b->len += n;
}

static void
put_fill (Buf *b, uint8_t v, size_t n)
{
    memset (b->data + b->len, v, n);
    b->len += n;
}

typedef struct
{
    const char *sni;      /* NULL: omit server_name */
    int ech;              /* add encrypted_client_hello extension */
    size_t key_share_len; /* 1216 + 32 emulates X25519MLKEM768 */
    size_t padding_len;   /* padding extension (0x0015), as Chrome sends */
    int duplicate_sni;
    int bad_ext_length;
} HelloSpec;

/* Builds a raw ClientHello handshake message (type + 24-bit length + body). */
static void
build_hello (const HelloSpec *spec, Buf *hs)
{
    Buf ext = { .len = 0 };
    Buf body = { .len = 0 };
    int i;

    for (i = 0; i < (spec->duplicate_sni ? 2 : 1) && spec->sni; i++) {
        const size_t n = strlen (spec->sni);
        put16 (&ext, 0x0000);
        put16 (&ext, (uint16_t)(n + 5));
        put16 (&ext, (uint16_t)(n + 3));
        put8 (&ext, 0);
        put16 (&ext, (uint16_t)n);
        put_bytes (&ext, spec->sni, n);
    }
    /* supported_versions: TLS 1.3 */
    put16 (&ext, 0x002b);
    put16 (&ext, 3);
    put8 (&ext, 2);
    put16 (&ext, 0x0304);
    if (spec->key_share_len) {
        put16 (&ext, 0x0033);
        put16 (&ext, (uint16_t)(spec->key_share_len + 6));
        put16 (&ext, (uint16_t)(spec->key_share_len + 4));
        put16 (&ext, 0x11ec); /* X25519MLKEM768 */
        put16 (&ext, (uint16_t)spec->key_share_len);
        put_fill (&ext, 0xab, spec->key_share_len);
    }
    if (spec->padding_len) {
        put16 (&ext, 0x0015);
        put16 (&ext, (uint16_t)spec->padding_len);
        put_fill (&ext, 0, spec->padding_len);
    }
    if (spec->ech) {
        put16 (&ext, 0xfe0d);
        put16 (&ext, 40);
        put_fill (&ext, 0xcd, 40);
    }

    put16 (&body, 0x0303);        /* legacy_version */
    put_fill (&body, 0x11, 32);   /* random */
    put8 (&body, 32);             /* session id */
    put_fill (&body, 0x22, 32);
    put16 (&body, 4);             /* cipher suites */
    put16 (&body, 0x1301);
    put16 (&body, 0x1302);
    put8 (&body, 1);              /* compression */
    put8 (&body, 0);
    put16 (&body, (uint16_t)(ext.len + (spec->bad_ext_length ? 7 : 0)));
    put_bytes (&body, ext.data, ext.len);

    hs->len = 0;
    put8 (hs, 0x01);
    put8 (hs, (uint8_t)(body.len >> 16));
    put8 (hs, (uint8_t)(body.len >> 8));
    put8 (hs, (uint8_t)body.len);
    put_bytes (hs, body.data, body.len);
}

/* Wraps a handshake message into TLS records of at most record_size bytes. */
static void
wrap_records (const Buf *hs, size_t record_size, Buf *out)
{
    size_t off = 0;

    out->len = 0;
    while (off < hs->len) {
        size_t n = hs->len - off;
        if (n > record_size)
            n = record_size;
        put8 (out, 0x16);
        put16 (out, 0x0301);
        put16 (out, (uint16_t)n);
        put_bytes (out, hs->data + off, n);
        off += n;
    }
}

static AuraTlsSniResult
inspect (const Buf *b, char *sni, uint32_t *flags)
{
    return aura_inspect_tls_client_hello (b->data, (uint32_t)b->len, sni, 254,
                                          flags);
}

static void
test_basic_sni (void)
{
    HelloSpec spec = { .sni = "Example.COM" };
    Buf hs, rec;
    char sni[254];
    uint32_t flags = 99;

    build_hello (&spec, &hs);
    wrap_records (&hs, 16384, &rec);
    CHECK (inspect (&rec, sni, &flags) == AURA_TLS_SNI_ALLOWED, "basic allowed");
    CHECK (strcmp (sni, "example.com") == 0, "SNI is lower-cased");
    CHECK (flags == 0, "no ECH / SNI present");
}

static void
test_post_quantum_hello_split_across_tcp_segments (void)
{
    HelloSpec spec = { .sni = "pq.example.org", .key_share_len = 1216 + 32,
                       .padding_len = 400 };
    Buf hs, rec;
    char sni[254];
    uint32_t flags;
    size_t seg;

    build_hello (&spec, &hs);
    wrap_records (&hs, 16384, &rec);
    CHECK (rec.len > 1460, "PQ ClientHello exceeds one TCP MSS");

    /* Feed growing prefixes, as tls_inspection_append() does per segment. */
    for (seg = 536; seg < rec.len; seg += 536) {
        Buf prefix = { .len = seg };
        memcpy (prefix.data, rec.data, seg);
        CHECK (inspect (&prefix, sni, &flags) == AURA_TLS_SNI_INCOMPLETE,
               "partial PQ ClientHello is INCOMPLETE, not MALFORMED");
    }
    CHECK (inspect (&rec, sni, &flags) == AURA_TLS_SNI_ALLOWED,
           "complete PQ ClientHello allowed");
    CHECK (strcmp (sni, "pq.example.org") == 0, "PQ SNI extracted");
}

static void
test_hello_fragmented_across_tls_records (void)
{
    HelloSpec spec = { .sni = "frag.example.net", .key_share_len = 1248 };
    Buf hs, rec;
    char sni[254];
    uint32_t flags;

    build_hello (&spec, &hs);
    wrap_records (&hs, 97, &rec); /* many tiny records */
    CHECK (inspect (&rec, sni, &flags) == AURA_TLS_SNI_ALLOWED,
           "multi-record ClientHello allowed");
    CHECK (strcmp (sni, "frag.example.net") == 0, "multi-record SNI extracted");

    /* Fragment where even the 4-byte handshake header spans two records. */
    wrap_records (&hs, 2, &rec);
    CHECK (inspect (&rec, sni, &flags) == AURA_TLS_SNI_ALLOWED,
           "2-byte records allowed");
    CHECK (strcmp (sni, "frag.example.net") == 0, "2-byte record SNI");
}

static void
test_ech_and_no_sni_flags (void)
{
    HelloSpec ech = { .sni = "cloudflare-ech.com", .ech = 1 };
    HelloSpec nosni = { .sni = NULL };
    Buf hs, rec;
    char sni[254];
    uint32_t flags;

    build_hello (&ech, &hs);
    wrap_records (&hs, 16384, &rec);
    CHECK (inspect (&rec, sni, &flags) == AURA_TLS_SNI_ALLOWED, "ECH allowed");
    CHECK (flags & AURA_TLS_FLAG_ECH, "ECH flag set");
    CHECK (strcmp (sni, "cloudflare-ech.com") == 0, "outer SNI reported");

    build_hello (&nosni, &hs);
    wrap_records (&hs, 16384, &rec);
    CHECK (inspect (&rec, sni, &flags) == AURA_TLS_SNI_ALLOWED, "no-SNI allowed");
    CHECK (flags & AURA_TLS_FLAG_NO_SNI, "NO_SNI flag set");
    CHECK (sni[0] == '\0', "empty SNI buffer");
}

static void
test_rules_and_allowlist (void)
{
    HelloSpec spec = { 0 };
    Buf hs, rec;
    char sni[254];
    const char *allow[] = { "dns.google" };

    CHECK (aura_add_dynamic_sni_rule ("evil.example") == 1, "rule added");
    CHECK (aura_add_dynamic_sni_rule ("bad domain") == -1, "invalid rule");

    spec.sni = "c2.evil.example";
    build_hello (&spec, &hs);
    wrap_records (&hs, 16384, &rec);
    CHECK (inspect (&rec, sni, NULL) == AURA_TLS_SNI_BLOCKED, "subdomain blocked");

    spec.sni = "notevil.example";
    build_hello (&spec, &hs);
    wrap_records (&hs, 16384, &rec);
    CHECK (inspect (&rec, sni, NULL) == AURA_TLS_SNI_ALLOWED,
           "label boundary respected");

    spec.sni = "dns.google";
    build_hello (&spec, &hs);
    wrap_records (&hs, 16384, &rec);
    CHECK (inspect (&rec, sni, NULL) == AURA_TLS_SNI_BLOCKED,
           "built-in DoH resolver blocked");
    CHECK (aura_set_dynamic_sni_allowlist (allow, 1) == 1, "allowlist set");
    CHECK (inspect (&rec, sni, NULL) == AURA_TLS_SNI_ALLOWED,
           "allowlist overrides DoH rule");
    CHECK (aura_set_dynamic_sni_allowlist (NULL, 0) == 1, "allowlist cleared");
}

static void
test_malformed_and_non_tls (void)
{
    HelloSpec dup = { .sni = "a.example", .duplicate_sni = 1 };
    HelloSpec bad = { .sni = "a.example", .bad_ext_length = 1 };
    HelloSpec under = { .sni = "bad_host.example" };
    Buf hs, rec;
    const char http[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    Buf plain = { .len = sizeof (http) - 1 };
    uint8_t header_only[3] = { 0x16, 0x03, 0x01 };
    uint8_t wrong_version[6] = { 0x16, 0x02, 0x00, 0x00, 0x01, 0x01 };

    build_hello (&dup, &hs);
    wrap_records (&hs, 16384, &rec);
    CHECK (inspect (&rec, NULL, NULL) == AURA_TLS_SNI_MALFORMED,
           "duplicate server_name rejected");

    build_hello (&bad, &hs);
    wrap_records (&hs, 16384, &rec);
    CHECK (inspect (&rec, NULL, NULL) == AURA_TLS_SNI_INCOMPLETE ||
               inspect (&rec, NULL, NULL) == AURA_TLS_SNI_MALFORMED,
           "bad extension length never ALLOWED");

    build_hello (&under, &hs);
    wrap_records (&hs, 16384, &rec);
    CHECK (inspect (&rec, NULL, NULL) == AURA_TLS_SNI_MALFORMED,
           "non-LDH SNI rejected");

    memcpy (plain.data, http, plain.len);
    CHECK (inspect (&plain, NULL, NULL) == AURA_TLS_SNI_ALLOWED,
           "non-TLS payload passes through");
    CHECK (aura_inspect_tls_sni (header_only, 3, NULL, 0) ==
               AURA_TLS_SNI_INCOMPLETE,
           "short record header INCOMPLETE");
    CHECK (aura_inspect_tls_sni (wrong_version, 6, NULL, 0) ==
               AURA_TLS_SNI_MALFORMED,
           "wrong record version MALFORMED");
    CHECK (aura_inspect_tls_sni (NULL, 0, NULL, 0) == AURA_TLS_SNI_INCOMPLETE,
           "empty payload INCOMPLETE");
}

static void
test_truncated_sni_buffer (void)
{
    HelloSpec spec = { .sni = "long-subdomain.example.com" };
    Buf hs, rec;
    char small[8];

    build_hello (&spec, &hs);
    wrap_records (&hs, 16384, &rec);
    CHECK (aura_inspect_tls_client_hello (rec.data, (uint32_t)rec.len, small,
                                          sizeof (small), NULL) ==
               AURA_TLS_SNI_ALLOWED,
           "small SNI buffer still parses");
    CHECK (strlen (small) == sizeof (small) - 1, "SNI truncated and terminated");
}

static void
test_random_fuzz (void)
{
    HelloSpec spec = { .sni = "fuzz.example", .key_share_len = 1248, .ech = 1 };
    Buf hs, rec;
    unsigned int seed = 12345;
    int round;

    build_hello (&spec, &hs);
    wrap_records (&hs, 300, &rec);
    for (round = 0; round < 20000; round++) {
        Buf m = rec;
        int flips = 1 + (int)(rand_r (&seed) % 4);
        size_t cut = (size_t)rand_r (&seed) % (rec.len + 1);
        char sni[254];
        uint32_t flags;
        AuraTlsSniResult r;
        while (flips--)
            m.data[(size_t)rand_r (&seed) % m.len] ^=
                (uint8_t)(1u << (rand_r (&seed) % 8));
        m.len = cut;
        r = inspect (&m, sni, &flags);
        CHECK (r >= AURA_TLS_SNI_INCOMPLETE && r <= AURA_TLS_SNI_MALFORMED,
               "fuzz result in range");
        CHECK (strlen (sni) <= 253, "fuzz SNI bounded");
    }
}

int
main (void)
{
    test_basic_sni ();
    test_post_quantum_hello_split_across_tcp_segments ();
    test_hello_fragmented_across_tls_records ();
    test_ech_and_no_sni_flags ();
    test_rules_and_allowlist ();
    test_malformed_and_non_tls ();
    test_truncated_sni_buffer ();
    test_random_fuzz ();

    printf ("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
