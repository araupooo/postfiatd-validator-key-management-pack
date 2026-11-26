/* bench_sig.c — signature benchmark harness for the validator
 * key-management assessment.
 *
 * Measures key generation, signing, and verification throughput for the
 * post-quantum signature schemes named in FIPS 204 (ML-DSA) and FIPS 205
 * (SLH-DSA) using liboqs 0.14.0, on one thread. Two message sizes are
 * supported: a fixed 32-byte digest (the length postfiatd verifies via
 * sha512Half in src/libxrpl/protocol/PublicKey.cpp) and a 225-byte
 * validator-manifest payload (the smallest live manifest observed;
 * see data/key_inventory.json). The message size is a command-line
 * argument (default 32). The message
 * content is a fixed, non-secret repeating pattern, so runs are
 * comparable. No timestamps are printed; the driver script records the
 * run context in the log header instead, so the measurement block is
 * stable apart from the measured rates themselves.
 *
 * Correctness controls run before timing: a valid signature must verify,
 * and a signature with one flipped byte must fail. Every step is logged
 * as it happens (step lines), not only the final result.
 *
 * Build: cc -O2 -I<liboqs-src>/src -I<liboqs-build>/include bench_sig.c \
 *          -L<liboqs-build>/lib -loqs -lcrypto -o bench_sig
 *   (liboqs built with -DOQS_BUILD_ONLY_LIB=ON; link order matters.)
 *
 * Usage: ./bench_sig <alg-name> [verify-seconds] [sign-seconds] [msg-bytes]
 *   verify-seconds / sign-seconds default to 5. Signing is additionally
 *   capped at 25 iterations per algorithm so a run stays short; when the
 *   cap is hit the reported signing rate is a lower bound and the log
 *   says so.
 */
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double
now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int
main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr,
                "usage: %s <alg> [verify-seconds] [sign-seconds] "
                "[msg-bytes]\n",
                argv[0]);
        return 2;
    }
    const char *alg_name = argv[1];
    double verify_budget = argc > 2 ? atof(argv[2]) : 5.0;
    double sign_budget = argc > 3 ? atof(argv[3]) : 5.0;
    size_t msg_len = argc > 4 ? (size_t)atol(argv[4]) : 32;
    if (verify_budget <= 0)
        verify_budget = 5.0;
    if (sign_budget <= 0)
        sign_budget = 5.0;
    if (msg_len == 0 || msg_len > 65536)
        msg_len = 32;

    printf("liboqs_version: %s\n", OQS_VERSION_TEXT);
    printf("algorithm: %s\n", alg_name);
    printf("message_bytes: %zu\n", msg_len);

    /* Fixed repeating pattern message; deterministic across runs. */
    static const char pattern[] = "POSTFIAT-RELEASE-MANIFEST-";
    uint8_t *message = malloc(msg_len);
    if (!message)
    {
        printf("result: ALLOCATION_FAILED\n");
        return 1;
    }
    for (size_t i = 0; i < msg_len; i++)
        message[i] = (uint8_t)pattern[i % (sizeof(pattern) - 1)];

    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (sig == NULL)
    {
        printf("result: ALGORITHM_NOT_ENABLED\n");
        free(message);
        return 1;
    }
    printf("step: algorithm object created\n");
    printf("claimed_nist_level: %d\n", sig->claimed_nist_level);
    printf("length_public_key: %zu\n", sig->length_public_key);
    printf("length_secret_key: %zu\n", sig->length_secret_key);
    printf("length_signature: %zu\n", sig->length_signature);

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t sig_len = 0;
    if (!pk || !sk || !signature)
    {
        printf("result: ALLOCATION_FAILED\n");
        return 1;
    }

    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS)
    {
        printf("result: KEYPAIR_FAILED\n");
        return 1;
    }
    printf("step: keypair generated\n");
    if (OQS_SIG_sign(sig, signature, &sig_len, message, msg_len, sk) !=
        OQS_SUCCESS)
    {
        printf("result: SIGN_FAILED\n");
        return 1;
    }
    printf("step: first signature produced\n");
    printf("signature_len_produced: %zu\n", sig_len);
    if (sig_len != sig->length_signature)
    {
        printf("result: SIGNATURE_LENGTH_MISMATCH\n");
        return 1;
    }
    printf("step: produced signature length matches declared length\n");

    /* Correctness controls (run before timing). */
    OQS_STATUS rc =
        OQS_SIG_verify(sig, message, msg_len, signature, sig_len, pk);
    printf("control_valid_signature_verifies: %s\n",
           rc == OQS_SUCCESS ? "PASS" : "FAIL");
    if (rc != OQS_SUCCESS)
    {
        printf("result: VALID_SIGNATURE_REJECTED\n");
        return 1;
    }
    signature[0] ^= 0x01; /* tamper one byte */
    rc = OQS_SIG_verify(sig, message, msg_len, signature, sig_len, pk);
    printf("control_tampered_signature_rejected: %s\n",
           rc != OQS_SUCCESS ? "PASS" : "FAIL");
    if (rc == OQS_SUCCESS)
    {
        printf("result: TAMPERED_SIGNATURE_ACCEPTED\n");
        return 1;
    }
    signature[0] ^= 0x01; /* restore */
    printf("step: controls passed (valid verifies, tampered rejects)\n");

    /* Verification throughput: loop until the time budget is spent. */
    {
        size_t ops = 0;
        double start = now_sec();
        double end;
        do
        {
            if (OQS_SIG_verify(sig, message, msg_len, signature, sig_len,
                               pk) != OQS_SUCCESS)
            {
                printf("result: VERIFY_FAILED_DURING_TIMING\n");
                return 1;
            }
            ops++;
            end = now_sec();
        } while (end - start < verify_budget);
        double elapsed = end - start;
        printf("verify_ops: %zu\n", ops);
        printf("verify_seconds: %.6f\n", elapsed);
        printf("verify_ops_per_sec: %.3f\n", (double)ops / elapsed);
        printf("verify_usec_per_op: %.3f\n", elapsed * 1e6 / (double)ops);
    }

    /* Signing throughput: time-boxed, capped at 25 iterations so the
     * slowest scheme (SLH-DSA 's' variants) keeps the run short. */
    {
        size_t ops = 0;
        double start = now_sec();
        double end;
        do
        {
            size_t out_len = 0;
            if (OQS_SIG_sign(sig, signature, &out_len, message, msg_len,
                             sk) != OQS_SUCCESS)
            {
                printf("result: SIGN_FAILED_DURING_TIMING\n");
                return 1;
            }
            ops++;
            end = now_sec();
        } while (end - start < sign_budget && ops < 25);
        double elapsed = end - start;
        printf("sign_ops: %zu\n", ops);
        printf("sign_seconds: %.6f\n", elapsed);
        printf("sign_ops_per_sec: %.3f\n", (double)ops / elapsed);
        printf("sign_usec_per_op: %.3f\n", elapsed * 1e6 / (double)ops);
        if (ops >= 25)
            printf("sign_note: iteration cap of 25 reached; rate is a "
                   "lower bound\n");
    }

    /* Key-generation throughput: 10 fresh keypairs. */
    {
        size_t ops = 0;
        double start = now_sec();
        for (ops = 0; ops < 10; ops++)
        {
            if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS)
            {
                printf("result: KEYPAIR_FAILED_DURING_TIMING\n");
                return 1;
            }
        }
        double elapsed = now_sec() - start;
        printf("keypair_ops: %zu\n", ops);
        printf("keypair_seconds: %.6f\n", elapsed);
        printf("keypair_ops_per_sec: %.3f\n", (double)ops / elapsed);
    }

    printf("result: OK\n");
    OQS_SIG_free(sig);
    free(pk);
    free(sk);
    free(signature);
    free(message);
    return 0;
}
