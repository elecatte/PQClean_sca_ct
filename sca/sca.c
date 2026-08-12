#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <sched.h>           // For CPU affinity
#include <sys/resource.h>    // For process priority
#include <unistd.h>          // For getpid
#include <sys/wait.h>        // For waitpid
#include <stdint.h>

// Include McEliece6960119 (Level 5)
#include "crypto_kem/mceliece6960119/clean/api.h"

// Include HQC-256 (Level 5)
#include "crypto_kem/hqc-256/clean/api.h"

// Fixed/deterministic-secret control for randombytes() 
#include "randombytes_control.h"


#define SCA_ITERATIONS_DEFAULT 10  // samples PER GROUP (not total)
#define WARMUP_ITERATIONS 5
#define TVLA_THRESHOLD 4.5           // standard |t| detection threshold

// Default seed for every "fixed" stream in this program 
static const uint8_t DEFAULT_FIXED_SEED[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

// -------------------------------------------------------------------------
// HELPER FUNCTIONS (same as benchmark_mceliece_hqc.c)
// -------------------------------------------------------------------------

static inline uint64_t get_cpu_cycles(void) {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

static void set_cpu_affinity(int cpu_id) {
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (nprocs > 0 && (cpu_id < 0 || cpu_id >= nprocs)) {
        fprintf(stderr, "Warning: requested CPU %d out of range (0..%ld). Skipping affinity.\n", cpu_id, nprocs - 1);
        return;
    }
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) != 0) {
        perror("Warning: sched_setaffinity failed");
        printf("Continuing without CPU affinity...\n");
    }
}

static void set_high_priority(void) {
    if (setpriority(PRIO_PROCESS, 0, -20) != 0) {
        perror("Warning: setpriority failed (requires root)");
        printf("Continuing with normal priority...\n");
    }
}

static void warmup_cpu(void) {
    volatile double sum = 0.0;
    for (long i = 0; i < 1000000; i++) {
        sum += sqrt(i + 1.0);
    }
    if (sum == 0.0) {
        (void)sum;
    }
}

static double get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}

static size_t get_peak_memory_kb(void) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        return usage.ru_maxrss;
    }
    return 0;
}

static double calculate_mean(const double *values, int n) {
    if (n <= 0) return 0.0;
    double sum = 0.0;
    for (int i = 0; i < n; i++) sum += values[i];
    return sum / n;
}

static double calculate_variance(const double *values, int n, double mean) {
    if (n <= 1) return 0.0;
    double sum_sq_diff = 0.0;
    for (int i = 0; i < n; i++) {
        double diff = values[i] - mean;
        sum_sq_diff += diff * diff;
    }
    return sum_sq_diff / (n - 1); // sample variance
}

// Welch's t-test
static double welch_t_test(const double *a, int na, const double *b, int nb, double *dof_out) {
    double mean_a = calculate_mean(a, na);
    double mean_b = calculate_mean(b, nb);
    double var_a = calculate_variance(a, na, mean_a);
    double var_b = calculate_variance(b, nb, mean_b);

    double se_a = var_a / na; // standar error
    double se_b = var_b / nb;
    double se_total = se_a + se_b;
    if (se_total <= 0.0) {
        if (dof_out) *dof_out = 0.0;    // degree of freedom undefined if no variance
        return 0.0;
    }

    double t = (mean_a - mean_b) / sqrt(se_total);

    if (dof_out) {
        double num = se_total * se_total;
        double den = (se_a * se_a) / (na - 1) + (se_b * se_b) / (nb - 1);
        if (denominator > 0.0) {
                *dof_out = num / den;
            } else {
                *dof_out = 0.0;
            }    
    }
    return t;
}

// Fisher-Yates shuffle of a schedule array 
static void shuffle_schedule(int *arr, int n) {
    for (int i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}

// -------------------------------------------------------------------------
// PROCESS ISOLATION 
// -------------------------------------------------------------------------

static void run_isolated_void(void (*fn)(int), int iterations) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork failed");
        return;
    }
    if (pid == 0) {
        fn(iterations);
        fflush(stdout);
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
}

// -------------------------------------------------------------------------
// GENERIC KEM FUNCTION POINTER TYPES
// -------------------------------------------------------------------------

typedef int (*keypair_fn_t)(unsigned char *pk, unsigned char *sk);
typedef int (*enc_fn_t)(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
typedef int (*dec_fn_t)(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

// -------------------------------------------------------------------------
// KEYGEN SUB-EXPERIMENT: deterministic keygen vs real keygen
// -------------------------------------------------------------------------

typedef enum { KG_FIXED = 0, KG_REAL, NUM_KG_GROUPS } KeygenGroup;
static const char *KG_GROUP_NAMES[NUM_KG_GROUPS] = {
    "KG_fixed_randomness", "KG_real_randomness"
};

static void run_keygen_sca(const char *algo_name, keypair_fn_t keypair,
                            size_t pk_size, size_t sk_size,
                            int iterations, FILE *csv) {
    unsigned char *pk = malloc(pk_size);
    unsigned char *sk = malloc(sk_size);
    if (!pk || !sk) {
        fprintf(stderr, "Error: allocation failed in run_keygen_sca\n");
        free(pk); free(sk);
        return;
    }

    double *times[NUM_KG_GROUPS];
    double *cycles[NUM_KG_GROUPS];
    int counts[NUM_KG_GROUPS] = {0};
    for (int g = 0; g < NUM_KG_GROUPS; g++) {
        times[g] = malloc(iterations * sizeof(double));
        cycles[g] = malloc(iterations * sizeof(double));
        if (!times[g] || !cycles[g]) {
            fprintf(stderr, "Error: allocation failed in run_keygen_sca\n");
            for (int k = 0; k <= g; k++) { free(times[k]); free(cycles[k]); }
            free(pk); free(sk);
            return;
        }
    }

    int total = iterations * NUM_KG_GROUPS;
    int *schedule = malloc(total * sizeof(int));
    for (int i = 0; i < total; i++) {
        schedule[i] = i / iterations; // NUM_KG_GROUPS blocks of `iterations`, then shuffled
    }
    shuffle_schedule(schedule, total);

    printf("\n--------------------------------------------------\n");
    printf("  %s -- KEYGEN leakage test (fixed vs real randomness)\n", algo_name);
    printf("--------------------------------------------------\n");
    printf("Samples per group: %d (interleaved, %d total calls)\n", iterations, total);
    printf("Progress: ");
    fflush(stdout);

    randombytes_disable_fixed(); // start from a known, real-randomness state

    for (int i = 0; i < total; i++) {
        if (i % (total / 50 + 1) == 0) {
            printf(".");
            fflush(stdout);
        }

        int g = schedule[i];

        if (g == KG_FIXED) {
            randombytes_enable_fixed(); // always reseeds -> identical stream every call
        } else {
            randombytes_disable_fixed();
        }

        uint64_t cstart = get_cpu_cycles();
        double start = get_time_ns();
        keypair(pk, sk);
        double end = get_time_ns();
        uint64_t cend = get_cpu_cycles();

        randombytes_disable_fixed(); // restore real mode immediately after, always

        int idx = counts[g]++;
        times[g][idx] = (end - start) / 1e6;
        cycles[g][idx] = (double)(cend - cstart);

        fprintf(csv, "keygen,%s,%d,%.6f,%.0f\n", KG_GROUP_NAMES[g], idx, times[g][idx], cycles[g][idx]);
    }
    printf(" Done!\n");

    printf("\nResults (mean +/- stddev, ms):\n");
    for (int g = 0; g < NUM_KG_GROUPS; g++) {
        double mean = calculate_mean(times[g], counts[g]);
        double var = calculate_variance(times[g], counts[g], mean);
        printf("\t%-24s %.4f +/- %.4f  (n=%d)\n", KG_GROUP_NAMES[g], mean, sqrt(var), counts[g]);
    }

    double dof;
    double t = welch_t_test(times[KG_FIXED], counts[KG_FIXED], times[KG_REAL], counts[KG_REAL], &dof);
    printf("\nWelch's t-test, %s vs %s:\n", KG_GROUP_NAMES[KG_FIXED], KG_GROUP_NAMES[KG_REAL]);
    printf("\tt = %.3f (dof ~ %.1f)\n", t, dof);
    printf("\tVerdict: %s (threshold |t| > %.1f)\n",
           fabs(t) > TVLA_THRESHOLD ? "LEAKAGE DETECTED" : "no leakage detected at this sample size",
           TVLA_THRESHOLD);

    for (int g = 0; g < NUM_KG_GROUPS; g++) { free(times[g]); free(cycles[g]); }
    free(schedule);
    free(pk); free(sk);
}

// -------------------------------------------------------------------------
// ENCAPS/DECAPS SUB-EXPERIMENT
// -------------------------------------------------------------------------

typedef enum {
    GROUP_0_FIXED_KEY_FIXED_INPUT = 0,
    GROUP_A_FIXED_KEY_RANDOM_INPUT,
    GROUP_B_FRESH_KEY_FIXED_INPUT,   
    GROUP_C_FRESH_KEY_RANDOM_INPUT,  
    NUM_GROUPS
} SCAGroup;

static const char *GROUP_NAMES[NUM_GROUPS] = {
    "G0_fixedKey_fixedInput",
    "A_fixedKey_randomInput",
    "B_freshKey_fixedInput",
    "C_freshKey_randomInput"
};

static void run_enc_dec_sca(const char *algo_name,
                             keypair_fn_t keypair, enc_fn_t enc, dec_fn_t dec,
                             size_t pk_size, size_t sk_size, size_t ct_size, size_t ss_size,
                             int iterations, FILE *csv) {
    unsigned char *fixed_pk = malloc(pk_size);
    unsigned char *fixed_sk = malloc(sk_size);
    // Scratch buffers reused for groups B and C (fresh key every time their turn comes up)
    unsigned char *fresh_pk = malloc(pk_size);
    unsigned char *fresh_sk = malloc(sk_size);
    unsigned char *ct = malloc(ct_size);
    unsigned char *ss_enc = malloc(ss_size);
    unsigned char *ss_dec = malloc(ss_size);

    if (!fixed_pk || !fixed_sk || !fresh_pk || !fresh_sk || !ct || !ss_enc || !ss_dec) {
        fprintf(stderr, "Error: allocation failed in run_enc_dec_sca\n");
        free(fixed_pk); free(fixed_sk); free(fresh_pk); free(fresh_sk);
        free(ct); free(ss_enc); free(ss_dec);
        return;
    }

    randombytes_enable_fixed();
    keypair(fixed_pk, fixed_sk);
    randombytes_disable_fixed();

    double *enc_times[NUM_GROUPS], *enc_cycles[NUM_GROUPS];
    double *dec_times[NUM_GROUPS], *dec_cycles[NUM_GROUPS];
    double *kg_times[NUM_GROUPS],  *kg_cycles[NUM_GROUPS]; // only populated for B, C
    int counts[NUM_GROUPS] = {0};
    int mismatches[NUM_GROUPS] = {0};

    for (int g = 0; g < NUM_GROUPS; g++) {
        enc_times[g] = malloc(iterations * sizeof(double));
        enc_cycles[g] = malloc(iterations * sizeof(double));
        dec_times[g] = malloc(iterations * sizeof(double));
        dec_cycles[g] = malloc(iterations * sizeof(double));
        kg_times[g] = malloc(iterations * sizeof(double));
        kg_cycles[g] = malloc(iterations * sizeof(double));
        if (!enc_times[g] || !enc_cycles[g] || !dec_times[g] || !dec_cycles[g] || !kg_times[g] || !kg_cycles[g]) {
            fprintf(stderr, "Error: allocation failed in run_enc_dec_sca\n");
            for (int k = 0; k <= g; k++) {
                free(enc_times[k]); free(enc_cycles[k]);
                free(dec_times[k]); free(dec_cycles[k]);
                free(kg_times[k]); free(kg_cycles[k]);
            }
            free(fixed_pk); free(fixed_sk); free(fresh_pk); free(fresh_sk);
            free(ct); free(ss_enc); free(ss_dec);
            return;
        }
    }

    int total = iterations * NUM_GROUPS;
    int *schedule = malloc(total * sizeof(int));
    for (int i = 0; i < total; i++) {
        schedule[i] = i / iterations;
    }
    shuffle_schedule(schedule, total);

    printf("\n--------------------------------------------------\n");
    printf("  %s -- ENCAPS/DECAPS leakage test (2x2 design)\n", algo_name);
    printf("--------------------------------------------------\n");
    printf("Groups: G0=fixedKey/fixedInput  A=fixedKey/randomInput\n");
    printf("        B=freshKey/fixedInput   C=freshKey/randomInput\n");
    printf("Samples per group: %d (interleaved, %d total rounds)\n", iterations, total);
    printf("Progress: ");
    fflush(stdout);

    randombytes_disable_fixed(); // known starting state

    for (int i = 0; i < total; i++) {
        if (i % (total / 50 + 1) == 0) {
            printf(".");
            fflush(stdout);
        }

        int g = schedule[i];
        unsigned char *use_pk, *use_sk;

        if (g == GROUP_0_FIXED_KEY_FIXED_INPUT || g == GROUP_A_FIXED_KEY_RANDOM_INPUT) {
            // Reuse the persistent fixed key -- no keygen call this round.
            use_pk = fixed_pk;
            use_sk = fixed_sk;
        } else {
            // GROUP_B or GROUP_C: fresh key every time, real randomness
            randombytes_disable_fixed();

            uint64_t kg_cstart = get_cpu_cycles();
            double kg_start = get_time_ns();
            keypair(fresh_pk, fresh_sk);
            double kg_end = get_time_ns();
            uint64_t kg_cend = get_cpu_cycles();

            int kidx = 0; // temp; real index assigned after counts[g] known below
            (void)kidx;
            kg_times[g][counts[g]] = (kg_end - kg_start) / 1e6;
            kg_cycles[g][counts[g]] = (double)(kg_cend - kg_cstart);

            use_pk = fresh_pk;
            use_sk = fresh_sk;
        }

        if (g == GROUP_0_FIXED_KEY_FIXED_INPUT || g == GROUP_B_FRESH_KEY_FIXED_INPUT) {
            randombytes_enable_fixed(); // reseeds -> identical stream every time
        } else {
            randombytes_disable_fixed();
        }

        uint64_t enc_cstart = get_cpu_cycles();
        double enc_start = get_time_ns();
        enc(ct, ss_enc, use_pk);
        double enc_end = get_time_ns();
        uint64_t enc_cend = get_cpu_cycles();

        randombytes_disable_fixed(); // restore real mode immediately, regardless of group

        uint64_t dec_cstart = get_cpu_cycles();
        double dec_start = get_time_ns();
        dec(ss_dec, ct, use_sk);
        double dec_end = get_time_ns();
        uint64_t dec_cend = get_cpu_cycles();

        int idx = counts[g]++;
        enc_times[g][idx] = (enc_end - enc_start) / 1e6;
        enc_cycles[g][idx] = (double)(enc_cend - enc_cstart);
        dec_times[g][idx] = (dec_end - dec_start) / 1e6;
        dec_cycles[g][idx] = (double)(dec_cend - dec_cstart);

        if (memcmp(ss_enc, ss_dec, ss_size) != 0) {
            mismatches[g]++;
        }

        if (g == GROUP_B_FRESH_KEY_FIXED_INPUT || g == GROUP_C_FRESH_KEY_RANDOM_INPUT) {
            fprintf(csv, "keygen,%s,%d,%.6f,%.0f\n", GROUP_NAMES[g], idx, kg_times[g][idx], kg_cycles[g][idx]);
        }
        fprintf(csv, "encaps,%s,%d,%.6f,%.0f\n", GROUP_NAMES[g], idx, enc_times[g][idx], enc_cycles[g][idx]);
        fprintf(csv, "decaps,%s,%d,%.6f,%.0f\n", GROUP_NAMES[g], idx, dec_times[g][idx], dec_cycles[g][idx]);
    }
    printf(" Done!\n");

    printf("\nCorrectness (mismatches / n per group):\n");
    for (int g = 0; g < NUM_GROUPS; g++) {
        printf("\t%-24s %d / %d\n", GROUP_NAMES[g], mismatches[g], counts[g]);
    }

    printf("\nEncapsulation results (mean +/- stddev, ms):\n");
    for (int g = 0; g < NUM_GROUPS; g++) {
        double mean = calculate_mean(enc_times[g], counts[g]);
        double var = calculate_variance(enc_times[g], counts[g], mean);
        printf("\t%-24s %.4f +/- %.4f  (n=%d)\n", GROUP_NAMES[g], mean, sqrt(var), counts[g]);
    }
    printf("\nDecapsulation results (mean +/- stddev, ms):\n");
    for (int g = 0; g < NUM_GROUPS; g++) {
        double mean = calculate_mean(dec_times[g], counts[g]);
        double var = calculate_variance(dec_times[g], counts[g], mean);
        printf("\t%-24s %.4f +/- %.4f  (n=%d)\n", GROUP_NAMES[g], mean, sqrt(var), counts[g]);
    }

    struct { const char *label; SCAGroup a; SCAGroup b; } comparisons[] = {
        {"G0 vs A  (input-dependent, fixed key)", GROUP_0_FIXED_KEY_FIXED_INPUT, GROUP_A_FIXED_KEY_RANDOM_INPUT},
        {"G0 vs B  (key-dependent, fixed input)",  GROUP_0_FIXED_KEY_FIXED_INPUT, GROUP_B_FRESH_KEY_FIXED_INPUT},
        {"A  vs C  (key-dependent, random input)", GROUP_A_FIXED_KEY_RANDOM_INPUT, GROUP_C_FRESH_KEY_RANDOM_INPUT},
        {"B  vs C  (keygen consistency check)",     GROUP_B_FRESH_KEY_FIXED_INPUT, GROUP_C_FRESH_KEY_RANDOM_INPUT},
    };
    int n_comp = (int)(sizeof(comparisons) / sizeof(comparisons[0]));

    printf("\nWelch's t-test -- ENCAPSULATION (threshold |t| > %.1f):\n", TVLA_THRESHOLD);
    for (int c = 0; c < n_comp; c++) {
        double dof;
        double t = welch_t_test(enc_times[comparisons[c].a], counts[comparisons[c].a],
                                 enc_times[comparisons[c].b], counts[comparisons[c].b], &dof);
        printf("\t%-40s t = %8.3f (dof ~ %6.1f)  %s\n",
               comparisons[c].label, t, dof,
               fabs(t) > TVLA_THRESHOLD ? "-> LEAKAGE DETECTED" : "-> no leakage detected");
    }

    printf("\nWelch's t-test -- DECAPSULATION (threshold |t| > %.1f):\n", TVLA_THRESHOLD);
    for (int c = 0; c < n_comp; c++) {
        double dof;
        double t = welch_t_test(dec_times[comparisons[c].a], counts[comparisons[c].a],
                                 dec_times[comparisons[c].b], counts[comparisons[c].b], &dof);
        printf("\t%-40s t = %8.3f (dof ~ %6.1f)  %s\n",
               comparisons[c].label, t, dof,
               fabs(t) > TVLA_THRESHOLD ? "-> LEAKAGE DETECTED" : "-> no leakage detected");
    }

    printf("\nNote: reported t-statistics use wall-clock time; the raw CSV also\n");
    printf("carries CPU cycle counts per sample for a second, independent look,\n");
    printf("and per-sample rows for histogram/multimodality inspection offline.\n");

    printf("\nPeak memory for this process (whole-process high-water mark,\n");
    printf("not meaningful per-group/per-iteration): %zu KB\n", get_peak_memory_kb());

    for (int g = 0; g < NUM_GROUPS; g++) {
        free(enc_times[g]); free(enc_cycles[g]);
        free(dec_times[g]); free(dec_cycles[g]);
        free(kg_times[g]); free(kg_cycles[g]);
    }
    free(schedule);
    free(fixed_pk); free(fixed_sk); free(fresh_pk); free(fresh_sk);
    free(ct); free(ss_enc); free(ss_dec);
}

// -------------------------------------------------------------------------
// PER-ALGORITHM ENTRY POINTS (these are what get forked/isolated)
// -------------------------------------------------------------------------

static void warmup_algorithm_mceliece(void) {
    size_t pk_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES;
    size_t sk_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES;
    unsigned char *pk = malloc(pk_size);
    unsigned char *sk = malloc(sk_size);
    if (!pk || !sk) { free(pk); free(sk); return; }
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pk, sk);
    }
    free(pk); free(sk);
}

static void warmup_algorithm_hqc(void) {
    size_t pk_size = PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES;
    size_t sk_size = PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES;
    unsigned char *pk = malloc(pk_size);
    unsigned char *sk = malloc(sk_size);
    if (!pk || !sk) { free(pk); free(sk); return; }
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pk, sk);
    }
    free(pk); free(sk);
}

static void run_mceliece_sca(int iterations) {
    set_cpu_affinity(0);
    set_high_priority();
    warmup_cpu();
    warmup_algorithm_mceliece();

    FILE *csv = fopen("sca_mceliece_raw.csv", "w");
    if (!csv) {
        perror("fopen sca_mceliece_raw.csv");
        return;
    }
    fprintf(csv, "phase,group,index,time_ms,cycles\n");

    run_keygen_sca("McEliece6960119",
                   (keypair_fn_t)PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair,
                   PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES,
                   PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES,
                   iterations, csv);

    run_enc_dec_sca("McEliece6960119",
                     (keypair_fn_t)PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair,
                     (enc_fn_t)PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc,
                     (dec_fn_t)PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec,
                     PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES,
                     PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES,
                     PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                     PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES,
                     iterations, csv);

    fclose(csv);
    printf("\nRaw per-iteration samples written to sca_mceliece_raw.csv\n");
}

static void run_hqc_sca(int iterations) {
    set_cpu_affinity(0);
    set_high_priority();
    warmup_cpu();
    warmup_algorithm_hqc();

    FILE *csv = fopen("sca_hqc_raw.csv", "w");
    if (!csv) {
        perror("fopen sca_hqc_raw.csv");
        return;
    }
    fprintf(csv, "phase,group,index,time_ms,cycles\n");

    run_keygen_sca("HQC-256",
                   (keypair_fn_t)PQCLEAN_HQC256_CLEAN_crypto_kem_keypair,
                   PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES,
                   PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES,
                   iterations, csv);

    run_enc_dec_sca("HQC-256",
                     (keypair_fn_t)PQCLEAN_HQC256_CLEAN_crypto_kem_keypair,
                     (enc_fn_t)PQCLEAN_HQC256_CLEAN_crypto_kem_enc,
                     (dec_fn_t)PQCLEAN_HQC256_CLEAN_crypto_kem_dec,
                     PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES,
                     PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES,
                     PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                     PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES,
                     iterations, csv);

    fclose(csv);
    printf("\nRaw per-iteration samples written to sca_hqc_raw.csv\n");
}

// -------------------------------------------------------------------------
// MAIN
// -------------------------------------------------------------------------

int main(int argc, char **argv) {
    int iterations = SCA_ITERATIONS_DEFAULT;

    const char *iter_env = getenv("SCA_ITERATIONS");
    if (iter_env) {
        int v = atoi(iter_env);
        if (v > 0) iterations = v;
    }
    if (argc > 1) {
        int v = atoi(argv[1]);
        if (v > 0) iterations = v;
    }

    randombytes_set_fixed_seed(DEFAULT_FIXED_SEED, sizeof(DEFAULT_FIXED_SEED));
    const char *seed_hex = getenv("SCA_FIXED_SEED_HEX");
    if (seed_hex && randombytes_set_fixed_seed_hex(seed_hex) != 0) {
        fprintf(stderr, "Warning: SCA_FIXED_SEED_HEX is not valid hex, using default seed.\n");
        randombytes_set_fixed_seed(DEFAULT_FIXED_SEED, sizeof(DEFAULT_FIXED_SEED));
    }

    srand((unsigned int)(time(NULL) ^ getpid()));

    printf("\n");
    printf("==================================================\n");
    printf("                                                  \n");
    printf("    SIDE-CHANNEL LEAKAGE TEST (macro/timing)     \n");
    printf("    McEliece6960119 vs HQC-256                   \n");
    printf("                                                  \n");
    printf("    Library: PQClean                             \n");
    printf("    Design: interleaved 2x2 (key x input)        \n");
    printf("    + keygen fixed-vs-real sanity check          \n");
    printf("    Samples per group: %6d                    \n", iterations);
    printf("                                                  \n");
    printf("==================================================\n");

    printf("\nConfiguration:\n");
    printf("\t* Samples per group:\t%d (override: argv[1] or SCA_ITERATIONS env var)\n", iterations);
    printf("\t* Warm-up iterations:\t%d\n", WARMUP_ITERATIONS);
    printf("\t* Timing precision:\tnanosecond (CLOCK_MONOTONIC_RAW) + rdtsc cycles\n");
    printf("\t* CPU affinity:\t\tenabled (core 0)\n");
    printf("\t* Process priority:\thigh (requires root for full effect)\n");
    printf("\t* TVLA threshold:\t|t| > %.1f\n", TVLA_THRESHOLD);
    printf("\t* Fixed seed:\t\tdefault built-in (override: SCA_FIXED_SEED_HEX env var)\n");
    printf("\nSee the block comment at the top of this file for the scope and\n");
    printf("limitations of a process-level macro channel like this one.\n");

    run_isolated_void(run_mceliece_sca, iterations);
    run_isolated_void(run_hqc_sca, iterations);

    printf("\n==================================================\n");
    printf("Done. Raw samples: sca_mceliece_raw.csv, sca_hqc_raw.csv\n");
    printf("Columns: phase,group,index,time_ms,cycles\n");
    printf("==================================================\n");

    return 0;
}