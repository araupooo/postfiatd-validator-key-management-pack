/* hybrid_bench.c — concatenated dual-signature benchmark for the
 * validator key-management assessment.
 *
 * Signs a fixed 225-byte validator-manifest payload with TWO schemes at
 * once and verifies BOTH halves; the hybrid signature is accepted only
 * when every half verifies. This is the concatenated dual-signature
 * design recommended in docs/PQ_MIGRATION.md (design H-1): the
 * classical half keeps compatibility with today's verifiers, the
 * post-quantum half keeps the signature valid against a quantum
 * adversary, and neither half alone is accepted.
 *
 * Classical half: Ed25519 via OpenSSL EVP (the scheme postfiatd itself
 * uses for Ed25519 keys; see src/libxrpl/protocol/SecretKey.cpp:263-266,
 * Buffer b(64)). Post-quantum halves: ML-DSA-44 and SLH-DSA-SHA2-128f
 * via liboqs 0.14.0 (registered under the SPHINCS+ name
 * SPHINCS+-SHA2-128f-simple; see docs/PQ_MIGRATION.md).
 *
 * Controls, run before timing and logged per step:
 *   C-1 valid hybrid signature verifies (both halves).
 *   C-2 flipping one byte in the classical half rejects.
 *   C-3 flipping one byte in the post-quantum half rejects.
 *   C-4 stripping the post-quantum half (classical-only, i.e. the
 *       downgrade attempt) rejects by length check.
 *   C-5 stripping the classical half rejects by length check.
 *
 * Build: cc -O2 -I<liboqs-src>/src -I<liboqs-build>/include \
 *          hybrid_bench.c -L<liboqs-build>/lib -loqs -lcrypto \
 *          -o hybrid_bench
 *
 * Usage: ./hybrid_bench [verify-seconds] [sign-seconds]
 *   Defaults: 5 s each. Signing is capped at 50 iterations per hybrid
 *   so the run stays short; when the cap is hit the reported signing
 *   rate is a lower bound and the log says so. No timestamps are
 *   printed; only measured rates vary between runs.
 */
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MANIFEST_BYTES 225

static double
now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Verify one hybrid signature: both halves must verify. Returns 1 on
 * accept, 0 on reject. Prints the per-half outcome (verbose step log).
 * g_pq_pk points at the current post-quantum public key (owned by
 * run_one()). */
static uint8_t *g_pq_pk = NULL;

static int
hybrid_verify(EVP_PKEY *ed_pkey, OQS_SIG *pq, const char *pq_display,
              const uint8_t *msg, size_t msg_len, const uint8_t *hybrid_sig,
              size_t hybrid_len, size_t ed_sig_len, int log_steps)
{
    size_t pq_sig_len = pq->length_signature;
    if (hybrid_len != ed_sig_len + pq_sig_len)
    {
        if (log_steps)
            printf("  step: hybrid length check FAIL (got %zu, want %zu)\n",
                   hybrid_len, ed_sig_len + pq_sig_len);
        return 0;
    }
    const uint8_t *ed_sig = hybrid_sig;
    const uint8_t *pq_sig = hybrid_sig + ed_sig_len;

    /* Classical half. */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return 0;
    int ed_ok = 0;
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, ed_pkey) == 1 &&
        EVP_DigestVerify(ctx, ed_sig, ed_sig_len, msg, msg_len) == 1)
        ed_ok = 1;
    EVP_MD_CTX_free(ctx);
    if (log_steps)
        printf("  step: classical (Ed25519) half verify: %s\n",
               ed_ok ? "PASS" : "FAIL");
    if (!ed_ok)
        return 0;

    /* Post-quantum half. */
    OQS_STATUS rc =
        OQS_SIG_verify(pq, msg, msg_len, pq_sig, pq_sig_len, g_pq_pk);
    if (log_steps)
        printf("  step: post-quantum (%s) half verify: %s\n", pq_display,
               rc == OQS_SUCCESS ? "PASS" : "FAIL");
    return rc == OQS_SUCCESS;
}

static int
run_one(const char *pq_display, const char *pq_liboqs_name,
        double verify_budget, double sign_budget, EVP_PKEY *ed_pkey,
        const uint8_t *msg, size_t msg_len)
{
    printf("--- hybrid: Ed25519 + %s ---\n", pq_display);
    printf("liboqs_algorithm_name: %s\n", pq_liboqs_name);

    OQS_SIG *pq = OQS_SIG_new(pq_liboqs_name);
    if (pq == NULL)
    {
        printf("result: ALGORITHM_NOT_ENABLED\n");
        return 1;
    }
    printf("step: post-quantum algorithm object created\n");
    printf("pq_length_public_key: %zu\n", pq->length_public_key);
    printf("pq_length_secret_key: %zu\n", pq->length_secret_key);
    printf("pq_length_signature: %zu\n", pq->length_signature);

    uint8_t *pq_pk = malloc(pq->length_public_key);
    uint8_t *pq_sk = malloc(pq->length_secret_key);
    if (!pq_pk || !pq_sk)
    {
        printf("result: ALLOCATION_FAILED\n");
        return 1;
    }
    g_pq_pk = pq_pk;
    if (OQS_SIG_keypair(pq, pq_pk, pq_sk) != OQS_SUCCESS)
    {
        printf("result: KEYPAIR_FAILED\n");
        return 1;
    }
    printf("step: post-quantum keypair generated\n");

    /* Classical half: Ed25519 via OpenSSL EVP, one-shot sign. */
    size_t ed_sig_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        printf("result: EVP_CONTEXT_FAILED\n");
        return 1;
    }
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, ed_pkey) != 1 ||
        EVP_DigestSign(ctx, NULL, &ed_sig_len, msg, msg_len) != 1)
    {
        printf("result: ED25519_SIGN_INIT_FAILED\n");
        return 1;
    }
    printf("ed25519_signature_len: %zu\n", ed_sig_len);

    size_t hybrid_len = ed_sig_len + pq->length_signature;
    uint8_t *hybrid_sig = malloc(hybrid_len);
    uint8_t *pq_sig = malloc(pq->length_signature);
    if (!hybrid_sig || !pq_sig)
    {
        printf("result: ALLOCATION_FAILED\n");
        return 1;
    }
    printf("hybrid_signature_len: %zu\n", hybrid_len);
    printf("hybrid_public_key_len: %zu\n", 32 + pq->length_public_key);
    printf("step: hybrid envelope size computed (classical + pq, no "
           "framing)\n");

    /* Sign both halves. */
    if (EVP_DigestSign(ctx, hybrid_sig, &ed_sig_len, msg, msg_len) != 1)
    {
        printf("result: ED25519_SIGN_FAILED\n");
        return 1;
    }
    EVP_MD_CTX_free(ctx);
    size_t pq_sig_len = 0;
    if (OQS_SIG_sign(pq, pq_sig, &pq_sig_len, msg, msg_len, pq_sk) !=
        OQS_SUCCESS)
    {
        printf("result: PQ_SIGN_FAILED\n");
        return 1;
    }
    memcpy(hybrid_sig + ed_sig_len, pq_sig, pq_sig_len);
    printf("step: both halves signed\n");

    /* C-1: valid hybrid signature verifies. */
    printf("control C-1 valid hybrid signature verifies:\n");
    int ok = hybrid_verify(ed_pkey, pq, pq_display, msg, msg_len,
                           hybrid_sig, hybrid_len, ed_sig_len, 1);
    printf("control C-1: %s\n", ok ? "PASS" : "FAIL");
    if (!ok)
    {
        printf("result: VALID_HYBRID_REJECTED\n");
        return 1;
    }

    /* C-2: tamper classical half. */
    hybrid_sig[0] ^= 0x01;
    printf("control C-2 tampered classical half rejected:\n");
    ok = hybrid_verify(ed_pkey, pq, pq_display, msg, msg_len,
                       hybrid_sig, hybrid_len, ed_sig_len, 1);
    printf("control C-2: %s\n", !ok ? "PASS" : "FAIL");
    hybrid_sig[0] ^= 0x01;
    if (ok)
    {
        printf("result: TAMPERED_CLASSICAL_HALF_ACCEPTED\n");
        return 1;
    }

    /* C-3: tamper post-quantum half. */
    hybrid_sig[ed_sig_len] ^= 0x01;
    printf("control C-3 tampered post-quantum half rejected:\n");
    ok = hybrid_verify(ed_pkey, pq, pq_display, msg, msg_len,
                       hybrid_sig, hybrid_len, ed_sig_len, 1);
    printf("control C-3: %s\n", !ok ? "PASS" : "FAIL");
    hybrid_sig[ed_sig_len] ^= 0x01;
    if (ok)
    {
        printf("result: TAMPERED_PQ_HALF_ACCEPTED\n");
        return 1;
    }

    /* C-4: strip the post-quantum half (downgrade to classical-only). */
    printf("control C-4 stripped post-quantum half (downgrade) rejected:\n");
    ok = hybrid_verify(ed_pkey, pq, pq_display, msg, msg_len,
                       hybrid_sig, ed_sig_len, ed_sig_len, 1);
    printf("control C-4: %s\n", !ok ? "PASS" : "FAIL");
    if (ok)
    {
        printf("result: DOWNGRADED_SIGNATURE_ACCEPTED\n");
        return 1;
    }

    /* C-5: strip the classical half. */
    printf("control C-5 stripped classical half rejected:\n");
    ok = hybrid_verify(ed_pkey, pq, pq_display, msg, msg_len,
                       hybrid_sig + ed_sig_len, pq->length_signature,
                       ed_sig_len, 1);
    printf("control C-5: %s\n", !ok ? "PASS" : "FAIL");
    if (ok)
    {
        printf("result: STRIPPED_CLASSICAL_HALF_ACCEPTED\n");
        return 1;
    }
    printf("step: controls passed (valid verifies; tamper and strip "
           "reject)\n");

    /* Hybrid verification throughput: both halves, every iteration. */
    {
        size_t ops = 0;
        double start = now_sec();
        double end;
        do
        {
            if (!hybrid_verify(ed_pkey, pq, pq_display, msg, msg_len,
                               hybrid_sig, hybrid_len, ed_sig_len, 0))
            {
                printf("result: VERIFY_FAILED_DURING_TIMING\n");
                return 1;
            }
            ops++;
            end = now_sec();
        } while (end - start < verify_budget);
        double elapsed = end - start;
        printf("hybrid_verify_ops: %zu\n", ops);
        printf("hybrid_verify_seconds: %.6f\n", elapsed);
        printf("hybrid_verify_ops_per_sec: %.3f\n", (double)ops / elapsed);
        printf("hybrid_verify_usec_per_op: %.3f\n",
               elapsed * 1e6 / (double)ops);
    }

    /* Hybrid signing throughput: both halves, capped at 50 iterations. */
    {
        size_t ops = 0;
        double start = now_sec();
        double end;
        do
        {
            /* EVP_DigestSign takes the buffer size in *siglen on entry;
             * an Ed25519 signature is always 64 bytes. */
            size_t out_ed = 64, out_pq = 0;
            EVP_MD_CTX *c2 = EVP_MD_CTX_new();
            if (!c2 ||
                EVP_DigestSignInit(c2, NULL, NULL, NULL, ed_pkey) != 1 ||
                EVP_DigestSign(c2, hybrid_sig, &out_ed, msg, msg_len) !=
                    1)
            {
                printf("result: ED25519_SIGN_FAILED_DURING_TIMING\n");
                return 1;
            }
            EVP_MD_CTX_free(c2);
            if (OQS_SIG_sign(pq, pq_sig, &out_pq, msg, msg_len, pq_sk) !=
                OQS_SUCCESS)
            {
                printf("result: PQ_SIGN_FAILED_DURING_TIMING\n");
                return 1;
            }
            memcpy(hybrid_sig + out_ed, pq_sig, out_pq);
            ops++;
            end = now_sec();
        } while (end - start < sign_budget && ops < 50);
        double elapsed = end - start;
        printf("hybrid_sign_ops: %zu\n", ops);
        printf("hybrid_sign_seconds: %.6f\n", elapsed);
        printf("hybrid_sign_ops_per_sec: %.3f\n", (double)ops / elapsed);
        printf("hybrid_sign_usec_per_op: %.3f\n",
               elapsed * 1e6 / (double)ops);
        if (ops >= 50)
            printf("hybrid_sign_note: iteration cap of 50 reached; rate "
                   "is a lower bound\n");
    }

    printf("result: OK\n");
    OQS_SIG_free(pq);
    free(pq_pk);
    free(pq_sk);
    free(hybrid_sig);
    free(pq_sig);
    g_pq_pk = NULL;
    return 0;
}

int
main(int argc, char **argv)
{
    double verify_budget = argc > 1 ? atof(argv[1]) : 5.0;
    double sign_budget = argc > 2 ? atof(argv[2]) : 5.0;
    if (verify_budget <= 0)
        verify_budget = 5.0;
    if (sign_budget <= 0)
        sign_budget = 5.0;

    printf("liboqs_version: %s\n", OQS_VERSION_TEXT);
    printf("manifest_bytes: %d\n", MANIFEST_BYTES);
    printf("message: fixed 225-byte validator-manifest payload "
           "(repeating pattern)\n");
    printf("threads: 1\n");

    static const char pattern[] = "POSTFIAT-RELEASE-MANIFEST-";
    static uint8_t msg[MANIFEST_BYTES];
    for (size_t i = 0; i < MANIFEST_BYTES; i++)
        msg[i] = (uint8_t)pattern[i % (sizeof(pattern) - 1)];

    /* One Ed25519 keypair, shared by both hybrid combinations. */
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!pctx)
    {
        printf("result: EVP_PKEY_CTX_FAILED\n");
        return 1;
    }
    EVP_PKEY *ed_pkey = NULL;
    if (EVP_PKEY_keygen_init(pctx) != 1 ||
        EVP_PKEY_keygen(pctx, &ed_pkey) != 1)
    {
        printf("result: ED25519_KEYGEN_FAILED\n");
        return 1;
    }
    EVP_PKEY_CTX_free(pctx);
    printf("step: Ed25519 keypair generated (OpenSSL EVP)\n");

    int rc = 0;
    rc |= run_one("ML-DSA-44", "ML-DSA-44", verify_budget, sign_budget,
                  ed_pkey, msg, MANIFEST_BYTES);
    printf("\n");
    rc |= run_one("SLH-DSA-SHA2-128f", "SPHINCS+-SHA2-128f-simple",
                  verify_budget, sign_budget, ed_pkey, msg, MANIFEST_BYTES);
    EVP_PKEY_free(ed_pkey);
    printf("result: %s\n", rc == 0 ? "OK" : "FAILED");
    return rc;
}
