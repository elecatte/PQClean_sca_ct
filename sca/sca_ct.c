#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <sched.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdint.h>

#include "crypto_kem/mceliece8192128f/clean/api.h"
#include "crypto_kem/hqc-256/clean/api.h"

#define NUM_MEASUREMENTS 10000
#define WARMUP_ITERATIONS 5
#define T_THRESHOLD 4.5

typedef int (*keypair_fn)(unsigned char *pk, unsigned char *sk);
typedef int (*enc_fn)(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
typedef int (*dec_fn)(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

typedef struct {
    const char *name;
    keypair_fn keypair;
    enc_fn encaps;
    dec_fn decaps;
    size_t pk_size, sk_size, ct_size, ss_size;
} KemAlgo;

// -------------------------------------------------------------------------
// HELPER 
// -------------------------------------------------------------------------
static inline uint64_t get_cpu_cycles() {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

void set_cpu_affinity(int cpu_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) != 0) {
        perror("Warning: sched_setaffinity failed");
    }
}

void set_high_priority() {
    if (setpriority(PRIO_PROCESS, 0, -20) != 0) {
        perror("Warning: setpriority failed (requires root)");
    }
}

void warmup_cpu() {
    volatile double sum = 0.0;
    for (long i = 0; i < 1000000; i++) sum += sqrt(i + 1.0);
    (void)sum;
}

double calculate_mean(double *v, int n) {
    double s = 0.0;
    for (int i = 0; i < n; i++) s += v[i];
    return s / n;
}

double calculate_var(double *v, int n, double mean) {
    double s = 0.0;
    for (int i = 0; i < n; i++) { double d = v[i] - mean; s += d * d; }
    return s / (n - 1);
}

// Function that implements Weltch t-test
double welch_t_test(double *a, int na, double *b, int nb) {
    double mean_a = calculate_mean(a, na);
    double mean_b = calculate_mean(b, nb);
    double var_a = calculate_var(a, na, mean_a);
    double var_b = calculate_var(b, nb, mean_b);
    double se = sqrt(var_a / na + var_b / nb);
    return (mean_a - mean_b) / se;
}

// Function to construct corrupted ciphertext by flipping n_bits random bits in buf of 
// length len bytes
void corrupt_ciphertext(unsigned char *buf, size_t len, int n_bits) {
    size_t total_bits = len * 8;
    if ((size_t)n_bits > total_bits) 
        n_bits = (int)total_bits;

    unsigned char *used = calloc(total_bits, 1);
    int flipped = 0;
    while (flipped < n_bits) {
        size_t bit_idx = ((size_t)rand() * (size_t)rand()) % total_bits;
        if (used[bit_idx]) continue;
        used[bit_idx] = 1;
        buf[bit_idx / 8] ^= (1 << (bit_idx % 8));
        flipped++;
    }
    free(used);
}

// -------------------------------------------------------------------------
// TEST fixed vs random ciphertexts
// -------------------------------------------------------------------------
void run_timing_test(KemAlgo *algo, int n_measurements) {
    printf("\n--------------------------------------------------\n");
    printf("  Timing leakage test (fixed vs random ciphertexts): %s\n", algo->name);
    printf("--------------------------------------------------\n");

    unsigned char *pk = malloc(algo->pk_size);
    unsigned char *sk = malloc(algo->sk_size);
    unsigned char *ct_fixed = malloc(algo->ct_size);
    unsigned char *ct_random = malloc(algo->ct_size);
    unsigned char *ss_tmp = malloc(algo->ss_size);
    unsigned char *ss_fixed = malloc(algo->ss_size);

    if (!pk || !sk || !ct_fixed || !ct_random || !ss_tmp || !ss_fixed) {
        fprintf(stderr, "Errore: allocazione memoria fallita\n");
        return;
    }

    // Only one keypair for the entire test
    algo->keypair(pk, sk);

    // Ciphertext fixed for misurations of class 0
    algo->encaps(ct_fixed, ss_fixed, pk);

    double *cycles_fixed = malloc(n_measurements * sizeof(double));
    double *cycles_random = malloc(n_measurements * sizeof(double));
    int n_fixed = 0, n_random = 0;

    printf("Warm-up...\n");
    for (int i = 0; i < WARMUP_ITERATIONS && i < n_measurements; i++) {
        algo->decaps(ss_tmp, ct_fixed, sk);
    }

    printf("Misurazione (%d campioni totali, ordine randomizzato)...\n", n_measurements);
    for (int i = 0; i < n_measurements; i++) {
        int cls = rand() % 2;

        if (cls == 0) {
            // Classe 0: fixed ciphertext
            uint64_t start = get_cpu_cycles();
            algo->decaps(ss_tmp, ct_fixed, sk);
            uint64_t end = get_cpu_cycles();
            cycles_fixed[n_fixed++] = (double)(end - start);
        } else {
            // Classe 1: fresh ciphertext
            algo->encaps(ct_random, ss_tmp, pk);
            uint64_t start = get_cpu_cycles();
            algo->decaps(ss_tmp, ct_random, sk);
            uint64_t end = get_cpu_cycles();
            cycles_random[n_random++] = (double)(end - start);
        }

        if (i % 500 == 0) { printf("."); fflush(stdout); }
    }
    printf(" Fatto!\n");
    printf("Campioni classe fixed:  %d\n", n_fixed);
    printf("Campioni classe random: %d\n", n_random);

    double mean_fixed = calculate_mean(cycles_fixed, n_fixed);
    double mean_random = calculate_mean(cycles_random, n_random);
    double t = welch_t_test(cycles_fixed, n_fixed, cycles_random, n_random);

    printf("\nRISULTATI:\n");
    printf("\tMedia cicli (fixed):  %.1f\n", mean_fixed);
    printf("\tMedia cicli (random): %.1f\n", mean_random);
    printf("\tDifferenza media:     %.1f cicli\n", mean_fixed - mean_random);
    printf("\tStatistica t di Welch: %.3f\n", t);
    if (fabs(t) > T_THRESHOLD) {
        printf("\t=> LEAK RILEVATO (|t| > %.1f)\n", T_THRESHOLD);
    } else {
        printf("\t=> Nessun leak rilevato in questo esperimento (|t| <= %.1f).\n", T_THRESHOLD);
    }

    // Save raw samples to CSV
    char filename[128];
    snprintf(filename, sizeof(filename), "%s_decaps_timing.csv", algo->name);
    FILE *f = fopen(filename, "w");
    if (f) {
        fprintf(f, "class,cycles\n");
        for (int i = 0; i < n_fixed; i++) fprintf(f, "fixed,%.0f\n", cycles_fixed[i]);
        for (int i = 0; i < n_random; i++) fprintf(f, "random,%.0f\n", cycles_random[i]);
        fclose(f);
        printf("\tCampioni grezzi salvati in: %s\n", filename);
    }

    free(pk); free(sk); free(ct_fixed); free(ct_random);
    free(ss_tmp); free(ss_fixed);
    free(cycles_fixed); free(cycles_random);
}

// -------------------------------------------------------------------------
// TEST valid vs corrupted ciphertexts
// -------------------------------------------------------------------------
void run_corrupted_test(KemAlgo *algo, int n_measurements, int n_bits_flip, const char *label) {
    printf("\n--------------------------------------------------\n");
    printf("  Timing leakage test (valid vs corrupted ciphertexts): %s [%s]\n", algo->name, label);
    printf("  Bit corrotti per campione: %d su %zu totali\n", n_bits_flip, algo->ct_size * 8);
    printf("--------------------------------------------------\n");

    unsigned char *pk = malloc(algo->pk_size);
    unsigned char *sk = malloc(algo->sk_size);
    unsigned char *ct_valid = malloc(algo->ct_size);
    unsigned char *ct_corrupt = malloc(algo->ct_size);
    unsigned char *ss_tmp = malloc(algo->ss_size);

    if (!pk || !sk || !ct_valid || !ct_corrupt || !ss_tmp) {
        fprintf(stderr, "Errore: allocazione memoria fallita\n");
        return;
    }

    algo->keypair(pk, sk);

    double *cycles_valid = malloc(n_measurements * sizeof(double));
    double *cycles_corrupt = malloc(n_measurements * sizeof(double));
    int n_valid = 0, n_corrupt = 0;

    printf("Warm-up...\n");
    algo->encaps(ct_valid, ss_tmp, pk);
    for (int i = 0; i < WARMUP_ITERATIONS && i < n_measurements; i++) {
        algo->decaps(ss_tmp, ct_valid, sk);
    }

    printf("Misurazione (%d campioni totali, ordine randomizzato)...\n", n_measurements);
    for (int i = 0; i < n_measurements; i++) {
        // Fresh valid ciphertext for each measurement
        algo->encaps(ct_valid, ss_tmp, pk);

        int cls = rand() % 2;
        // Class 0: valid ciphertext
        if (cls == 0) {
            uint64_t start = get_cpu_cycles();
            algo->decaps(ss_tmp, ct_valid, sk);
            uint64_t end = get_cpu_cycles();
            cycles_valid[n_valid++] = (double)(end - start);
        } else {
            // Class 1: corrupted ciphertext
            memcpy(ct_corrupt, ct_valid, algo->ct_size);
            corrupt_ciphertext(ct_corrupt, algo->ct_size, n_bits_flip);

            uint64_t start = get_cpu_cycles();
            algo->decaps(ss_tmp, ct_corrupt, sk);
            uint64_t end = get_cpu_cycles();
            cycles_corrupt[n_corrupt++] = (double)(end - start);
        }

        if (i % 500 == 0) { printf("."); fflush(stdout); }
    }
    printf(" Fatto!\n");
    printf("Campioni classe valid:     %d\n", n_valid);
    printf("Campioni classe corrupted: %d\n", n_corrupt);

    double mean_valid = calculate_mean(cycles_valid, n_valid);
    double mean_corrupt = calculate_mean(cycles_corrupt, n_corrupt);
    double t = welch_t_test(cycles_valid, n_valid, cycles_corrupt, n_corrupt);

    printf("\nRISULTATI:\n");
    printf("\tMedia cicli (valid):     %.1f\n", mean_valid);
    printf("\tMedia cicli (corrupted): %.1f\n", mean_corrupt);
    printf("\tDifferenza media:        %.1f cicli\n", mean_valid - mean_corrupt);
    printf("\tStatistica t di Welch:   %.3f\n", t);
    if (fabs(t) > T_THRESHOLD) {
        printf("\t=> LEAK RILEVATO (|t| > %.1f)\n", T_THRESHOLD);
    } else {
        printf("\t=> Nessun leak rilevato in questo esperimento (|t| <= %.1f).\n", T_THRESHOLD);
    }

    // Save raw samples to CSV
    char filename[160];
    snprintf(filename, sizeof(filename), "%s_valid_vs_corrupted_%s.csv", algo->name, label);
    FILE *f = fopen(filename, "w");
    if (f) {
        fprintf(f, "class,cycles\n");
        for (int i = 0; i < n_valid; i++) fprintf(f, "valid,%.0f\n", cycles_valid[i]);
        for (int i = 0; i < n_corrupt; i++) fprintf(f, "corrupted,%.0f\n", cycles_corrupt[i]);
        fclose(f);
        printf("\tCampioni grezzi salvati in: %s\n", filename);
    }

    free(pk); free(sk); free(ct_valid); free(ct_corrupt); free(ss_tmp);
    free(cycles_valid); free(cycles_corrupt);
}

// -------------------------------------------------------------------------
// MAIN
// -------------------------------------------------------------------------
int main() {
    printf("==================================================\n");
    printf("  Timing leakage test\n");
    printf("  Libreria: PQClean\n");
    printf("==================================================\n");

    set_cpu_affinity(0);
    set_high_priority();
    warmup_cpu();
    srand((unsigned int)time(NULL));

    KemAlgo mceliece = {
        .name = "mceliece8192128f",
        .keypair = (keypair_fn)PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_keypair,
        .encaps = (enc_fn)PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_enc,
        .decaps = (dec_fn)PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_dec,
        .pk_size = PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_PUBLICKEYBYTES,
        .sk_size = PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_SECRETKEYBYTES,
        .ct_size = PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
        .ss_size = PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_BYTES,
    };

    KemAlgo hqc = {
        .name = "hqc256",
        .keypair = (keypair_fn)PQCLEAN_HQC256_CLEAN_crypto_kem_keypair,
        .encaps = (enc_fn)PQCLEAN_HQC256_CLEAN_crypto_kem_enc,
        .decaps = (dec_fn)PQCLEAN_HQC256_CLEAN_crypto_kem_dec,
        .pk_size = PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES,
        .sk_size = PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES,
        .ct_size = PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES,
        .ss_size = PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES,
    };

    // Test 1: fixed vs random ciphertexts
    run_timing_test(&mceliece, NUM_MEASUREMENTS);
    //run_timing_test(&hqc, NUM_MEASUREMENTS);

    // Test 2: valid vs corrupted ciphertexts with 1 bit flipped
    run_corrupted_test(&mceliece, NUM_MEASUREMENTS, 1, "1bit");
    //run_corrupted_test(&hqc, NUM_MEASUREMENTS, 1, "1bit");

    // Test 3: valid vs corrupted ciphertexts with heavy corruption (4 bits per byte)
    run_corrupted_test(&mceliece, NUM_MEASUREMENTS, (int)(mceliece.ct_size * 4), "heavy");
    //run_corrupted_test(&hqc, NUM_MEASUREMENTS, (int)(hqc.ct_size * 4), "heavy");

    return 0;
}