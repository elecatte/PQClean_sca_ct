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

// Include McEliece6960119 (Level 5)
#include "crypto_kem/mceliece6960119/clean/api.h"

// Include HQC-256 (Level 5)
#include "crypto_kem/hqc-256/clean/api.h"

#define NUM_ITERATIONS 100    // Number of benchmark iterations  
#define WARMUP_ITERATIONS 5  // Warmup iterations

typedef struct {
    double keygen_mean;
    double keygen_stddev;
    double encaps_mean;
    double encaps_stddev;
    double decaps_mean;
    double decaps_stddev;
    size_t pk_size;
    size_t sk_size;
    size_t ct_size;
    size_t peak_memory_kb;
} BenchmarkResults;

// Function to set CPU affinity (best-effort)
void set_cpu_affinity(int cpu_id) {
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (nprocs > 0 && (cpu_id < 0 || cpu_id >= nprocs)) {
        fprintf(stderr, "Warning: requested CPU %d out of range (0..%ld). Skipping affinity.\n", cpu_id, nprocs - 1);
        return;
    }

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);        // clear all CPUs in the set
    CPU_SET(cpu_id, &cpuset); // add the requested CPU to the set
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) != 0) {
        perror("Warning: sched_setaffinity failed");
        printf("Continuing without CPU affinity...\n");
    }
}

// Function to set high priority
void set_high_priority() {
    if (setpriority(PRIO_PROCESS, 0, -20) != 0) {
        perror("Warning: setpriority failed (requires root)");
        printf("Continuing with normal priority...\n");
    }
}

// CPU warmup function
void warmup_cpu() {
    volatile double sum = 0.0;
    for (long i = 0; i < 1000000; i++) {
        sum += sqrt(i + 1.0);
    }
    // Prevent compiler optimization
    if (sum == 0.0) {
        (void)sum; // Dummy operation
    }
}

// Returns nanoseconds for higher precision
double get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}

// Function to get peak memory in KB
size_t get_peak_memory_kb() {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        return usage.ru_maxrss;  // KB in Linux
    }
    return 0;
}

// Calculate mean
double calculate_mean(double *values, int n) {
    double sum = 0.0;
    for (int i = 0; i < n; i++) {
        sum += values[i];
    }
    return sum / n;
}

// Calculate standard deviation
double calculate_stddev(double *values, int n, double mean) {
    double sum_sq_diff = 0.0;
    for (int i = 0; i < n; i++) {
        double diff = values[i] - mean;
        sum_sq_diff += diff * diff;
    }
    return sqrt(sum_sq_diff / n);
}

// Calculate 95% confidence interval
double calculate_confidence_interval(double stddev, int n) {
    // t-value for t-Student distribution
    double t_value;
    if (n >= 100) {
        t_value = 1.984;  // t for n=100
    } else if (n >= 30) {
        t_value = 2.042;  // t for n=30
    } else if (n == 10) {
        t_value = 2.228;
    } else {
        t_value = 2.571;  // conservative for small n, like n =5
    }
    return t_value * stddev / sqrt(n);
}


// Runs a benchmark in an isolated child process so its memory watermark
// (ru_maxrss) starts fresh, independent of any benchmark that ran before it.
BenchmarkResults run_isolated(BenchmarkResults (*bench_fn)(int), int iterations) {
    int pipefd[2];
    if (pipe(pipefd) != 0) { perror("pipe failed"); BenchmarkResults empty = {0}; return empty; }

    pid_t pid = fork();
    if (pid < 0) { perror("fork failed"); BenchmarkResults empty = {0}; return empty; }

    if (pid == 0) {
        // Child: run the benchmark, send results back through the pipe
        close(pipefd[0]);
        BenchmarkResults results = bench_fn(iterations);
        fflush(stdout);                      // ensure child's prints land before it exits
        write(pipefd[1], &results, sizeof(results));
        close(pipefd[1]);
        _exit(0);
    }

    // Parent: block until the child sends its results, then reap it
    close(pipefd[1]);
    BenchmarkResults results = {0};
    ssize_t n = read(pipefd[0], &results, sizeof(results));
    close(pipefd[0]);
    if (n != (ssize_t)sizeof(results)) fprintf(stderr, "Warning: incomplete results from child\n");
    int status;
    waitpid(pid, &status, 0);
    return results;
}



// Warmup function for McEliece algorithm   
void warmup_algorithm_mceliece() {
    size_t pk_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES;
    size_t sk_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES;
    
    unsigned char *warmup_pk = malloc(pk_size);
    unsigned char *warmup_sk = malloc(sk_size);
    
    if (!warmup_pk || !warmup_sk) {
        fprintf(stderr, "Error: Memory allocation failed in warmup_mceliece\n");
        free(warmup_pk);
        free(warmup_sk);
        return;
    }
    
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(warmup_pk, warmup_sk);
    }
    
    free(warmup_pk);
    free(warmup_sk);
}

// Warmup function for HQC algorithm
void warmup_algorithm_hqc() {
    size_t pk_size = PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES;
    size_t sk_size = PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES;
    
    unsigned char *warmup_pk = malloc(pk_size);
    unsigned char *warmup_sk = malloc(sk_size);
    
    if (!warmup_pk || !warmup_sk) {
        fprintf(stderr, "Error: Memory allocation failed in warmup_hqc\n");
        free(warmup_pk);
        free(warmup_sk);
        return;
    }
    
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(warmup_pk, warmup_sk);
    }
    
    free(warmup_pk);
    free(warmup_sk);
}

// Benchmark for McEliece
BenchmarkResults benchmark_mceliece(int iterations) {
    BenchmarkResults results = {0};
    
    results.pk_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES;
    results.sk_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES;
    results.ct_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    
    printf("\n--------------------------------------------------\n");
    printf("  McEliece6960119 (NIST Level 5 - AES-256 eq.)\n");
    printf("--------------------------------------------------\n");
    printf("Parameters: n=6960, k=5413, t=119\n");
    printf("Iterations: %d (Warm-up: %d)\n", iterations, WARMUP_ITERATIONS);
    
    // Benchmark environment setup
    printf("Setting up benchmark environment...\n");
    // Pin process to CPU 0 to reduce scheduling jitter and measurement noise
    set_cpu_affinity(0);
    set_high_priority();
    warmup_cpu();
    warmup_algorithm_mceliece();
    
    double *keygen_times = malloc(iterations * sizeof(double));
    double *encaps_times = malloc(iterations * sizeof(double));
    double *decaps_times = malloc(iterations * sizeof(double));
    
    if (!keygen_times || !encaps_times || !decaps_times) {
        fprintf(stderr, "Error: Memory allocation failed for timing arrays\n");
        free(keygen_times);
        free(encaps_times);
        free(decaps_times);
        return results;
    }
    
    printf("Benchmarking Key Generation...\nProgress: ");
    fflush(stdout);
    
    // Benchmark Key Generation
    for (int i = 0; i < iterations; i++) {
        if (i % 10 == 0) {
            printf(".");
            fflush(stdout);
        }
        
        unsigned char *pk = malloc(results.pk_size);
        unsigned char *sk = malloc(results.sk_size);
        
        if (!pk || !sk) {
            fprintf(stderr, "\nError: Memory allocation failed at iteration %d\n", i);
            free(pk);
            free(sk);
            break;
        }
        
        double start = get_time_ns();
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pk, sk);
        double end = get_time_ns();
        
        keygen_times[i] = (end - start) / 1e6;  // ns to ms
        
        free(pk);
        free(sk);
    }
    printf(" Done!\n");
    
    // Generate a keypair for subsequent tests
    unsigned char *pk = malloc(results.pk_size);
    unsigned char *sk = malloc(results.sk_size);
    unsigned char *ct = malloc(results.ct_size);
    unsigned char ss_enc[PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES];
    unsigned char ss_dec[PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES];
    
    if (!pk || !sk || !ct) {
        fprintf(stderr, "\nError: Memory allocation failed for main keys\n");
        free(pk);
        free(sk);
        free(ct);
        free(keygen_times);
        free(encaps_times);
        free(decaps_times);
        return results;
    }
    
    PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pk, sk);
    
    printf("Benchmarking Encapsulation...\nProgress: ");
    fflush(stdout);
    
    // Benchmark Encapsulation
    for (int i = 0; i < iterations; i++) {
        if (i % 10 == 0) {
            printf(".");
            fflush(stdout);
        }
        
        double start = get_time_ns();
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
        double end = get_time_ns();
        
        encaps_times[i] = (end - start) / 1e6;  // ns to ms
    }
    printf(" Done!\n");
    
    // Generate a ciphertext for decapsulation test
    PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
    
    printf("Benchmarking Decapsulation...\nProgress: ");
    fflush(stdout);
    
    // Benchmark Decapsulation
    for (int i = 0; i < iterations; i++) {
        if (i % 10 == 0) {
            printf(".");
            fflush(stdout);
        }
        
        double start = get_time_ns();
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec(ss_dec, ct, sk);
        double end = get_time_ns();
        
        decaps_times[i] = (end - start) / 1e6;  // ns to ms
    }
    printf(" Done!\n");
    
    // Calculate statistics
    results.keygen_mean = calculate_mean(keygen_times, iterations);
    results.keygen_stddev = calculate_stddev(keygen_times, iterations, results.keygen_mean);
    
    results.encaps_mean = calculate_mean(encaps_times, iterations);
    results.encaps_stddev = calculate_stddev(encaps_times, iterations, results.encaps_mean);
    
    results.decaps_mean = calculate_mean(decaps_times, iterations);
    results.decaps_stddev = calculate_stddev(decaps_times, iterations, results.decaps_mean);
    
    // Peak memory
    results.peak_memory_kb = get_peak_memory_kb();
    
    // Correctness verification
    if (memcmp(ss_enc, ss_dec, PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES) == 0) {
        printf("* Correctness verification: SUCCESS\n");
    } else {
        printf("* Correctness verification: FAILED\n");
    }
    
    free(pk);
    free(sk);
    free(ct);
    free(keygen_times);
    free(encaps_times);
    free(decaps_times);
    
    return results;
}

// Benchmark for HQC-256
BenchmarkResults benchmark_hqc(int iterations) {
    BenchmarkResults results = {0};
    
    results.pk_size = PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES;
    results.sk_size = PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES;
    results.ct_size = PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    
    printf("\n--------------------------------------------------\n");
    printf("  HQC-256 (NIST Level 5 - AES-256 equivalent)\n");
    printf("--------------------------------------------------\n");
    printf("Parameters: n=57637, k=256, w=131, wr=149, we=149 \n");
    printf("Iterations: %d (Warm-up: %d)\n", iterations, WARMUP_ITERATIONS);
    
    printf("Setting up benchmark environment...\n");
    // Pin process to CPU 0 to reduce scheduling jitter and measurement noise
    set_cpu_affinity(0);
    set_high_priority();
    warmup_cpu();
    warmup_algorithm_hqc();
    
    double *keygen_times = malloc(iterations * sizeof(double));
    double *encaps_times = malloc(iterations * sizeof(double));
    double *decaps_times = malloc(iterations * sizeof(double));
    
    if (!keygen_times || !encaps_times || !decaps_times) {
        fprintf(stderr, "Error: Memory allocation failed for timing arrays\n");
        free(keygen_times);
        free(encaps_times);
        free(decaps_times);
        return results;
    }
    
    printf("Benchmarking Key Generation...\nProgress: ");
    fflush(stdout);
    
    // Benchmark Key Generation
    for (int i = 0; i < iterations; i++) {
        if (i % 10 == 0) {
            printf(".");
            fflush(stdout);
        }
        
        unsigned char *pk = malloc(results.pk_size);
        unsigned char *sk = malloc(results.sk_size);
        
        if (!pk || !sk) {
            fprintf(stderr, "\nError: Memory allocation failed at iteration %d\n", i);
            free(pk);
            free(sk);
            break;
        }
        
        double start = get_time_ns();
        PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pk, sk);
        double end = get_time_ns();
        
        keygen_times[i] = (end - start) / 1e6;  // ns to ms
        
        free(pk);
        free(sk);
    }
    printf(" Done!\n");
    
    unsigned char *pk = malloc(results.pk_size);
    unsigned char *sk = malloc(results.sk_size);
    unsigned char *ct = malloc(results.ct_size);
    unsigned char ss_enc[PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES];
    unsigned char ss_dec[PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES];
    
    if (!pk || !sk || !ct) {
        fprintf(stderr, "\nError: Memory allocation failed for main keys\n");
        free(pk);
        free(sk);
        free(ct);
        free(keygen_times);
        free(encaps_times);
        free(decaps_times);
        return results;
    }
    
    PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pk, sk);
    
    printf("Benchmarking Encapsulation...\nProgress: ");
    fflush(stdout);
    
    // Benchmark Encapsulation
    for (int i = 0; i < iterations; i++) {
        if (i % 10 == 0) {
            printf(".");
            fflush(stdout);
        }
        
        double start = get_time_ns();
        PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
        double end = get_time_ns();
        
        encaps_times[i] = (end - start) / 1e6;  // ns to ms
    }
    printf(" Done!\n");
    
    PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
    
    printf("Benchmarking Decapsulation...\nProgress: ");
    fflush(stdout);
    
    // Benchmark Decapsulation
    for (int i = 0; i < iterations; i++) {
        if (i % 10 == 0) {
            printf(".");
            fflush(stdout);
        }
        
        double start = get_time_ns();
        PQCLEAN_HQC256_CLEAN_crypto_kem_dec(ss_dec, ct, sk);
        double end = get_time_ns();
        
        decaps_times[i] = (end - start) / 1e6;  // ns to ms
    }
    printf(" Done!\n");
    
    results.keygen_mean = calculate_mean(keygen_times, iterations);
    results.keygen_stddev = calculate_stddev(keygen_times, iterations, results.keygen_mean);
    
    results.encaps_mean = calculate_mean(encaps_times, iterations);
    results.encaps_stddev = calculate_stddev(encaps_times, iterations, results.encaps_mean);
    
    results.decaps_mean = calculate_mean(decaps_times, iterations);
    results.decaps_stddev = calculate_stddev(decaps_times, iterations, results.decaps_mean);
    
    results.peak_memory_kb = get_peak_memory_kb();
    
    if (memcmp(ss_enc, ss_dec, PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES) == 0) {
        printf("* Correctness verification: SUCCESS\n");
    } else {
        printf("* Correctness verification: FAILED\n");
    }
    
    free(pk);
    free(sk);
    free(ct);
    free(keygen_times);
    free(encaps_times);
    free(decaps_times);
    
    return results;
}


// Benchmark for McEliece using a fresh keypair on every iteration
BenchmarkResults benchmark_mceliece_fresh_keys(int iterations) {
    BenchmarkResults results = {0};

    results.pk_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES;
    results.sk_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES;
    results.ct_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES;

    printf("\n--------------------------------------------------\n");
    printf("  McEliece6960119 (fresh keypair per iteration)\n");
    printf("--------------------------------------------------\n");
    printf("Iterations: %d (Warm-up: %d)\n", iterations, WARMUP_ITERATIONS);

    printf("Setting up benchmark environment...\n");
    set_cpu_affinity(0);
    set_high_priority();
    warmup_cpu();
    warmup_algorithm_mceliece();

    double *keygen_times = malloc(iterations * sizeof(double));
    double *encaps_times = malloc(iterations * sizeof(double));
    double *decaps_times = malloc(iterations * sizeof(double));

    if (!keygen_times || !encaps_times || !decaps_times) {
        fprintf(stderr, "Error: Memory allocation failed for timing arrays\n");
        free(keygen_times);
        free(encaps_times);
        free(decaps_times);
        return results;
    }

    unsigned char *pk = malloc(results.pk_size);
    unsigned char *sk = malloc(results.sk_size);
    unsigned char *ct = malloc(results.ct_size);
    unsigned char ss_enc[PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES];
    unsigned char ss_dec[PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES];

    if (!pk || !sk || !ct) {
        fprintf(stderr, "Error: Memory allocation failed for main keys\n");
        free(pk); free(sk); free(ct);
        free(keygen_times); free(encaps_times); free(decaps_times);
        return results;
    }

    int failures = 0;

    printf("Benchmarking with a new keypair each iteration...\nProgress: ");
    fflush(stdout);

    for (int i = 0; i < iterations; i++) {
        if (i % 10 == 0) {
            printf(".");
            fflush(stdout);
        }

        // Fresh keypair for this iteration
        double kg_start = get_time_ns();
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pk, sk);
        double kg_end = get_time_ns();
        keygen_times[i] = (kg_end - kg_start) / 1e6;

        // Encapsulate with the fresh public key
        double enc_start = get_time_ns();
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
        double enc_end = get_time_ns();
        encaps_times[i] = (enc_end - enc_start) / 1e6;

        // Decapsulate with the matching fresh secret key
        double dec_start = get_time_ns();
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec(ss_dec, ct, sk);
        double dec_end = get_time_ns();
        decaps_times[i] = (dec_end - dec_start) / 1e6;

        if (memcmp(ss_enc, ss_dec, PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES) != 0) {
            failures++;
        }
    }
    printf(" Done!\n");

    results.keygen_mean = calculate_mean(keygen_times, iterations);
    results.keygen_stddev = calculate_stddev(keygen_times, iterations, results.keygen_mean);

    results.encaps_mean = calculate_mean(encaps_times, iterations);
    results.encaps_stddev = calculate_stddev(encaps_times, iterations, results.encaps_mean);

    results.decaps_mean = calculate_mean(decaps_times, iterations);
    results.decaps_stddev = calculate_stddev(decaps_times, iterations, results.decaps_mean);

    results.peak_memory_kb = get_peak_memory_kb();

    if (failures == 0) {
        printf("* Correctness verification: SUCCESS (%d/%d matched)\n", iterations, iterations);
    } else {
        printf("* Correctness verification: FAILED (%d/%d mismatched)\n", failures, iterations);
    }

    free(pk); free(sk); free(ct);
    free(keygen_times); free(encaps_times); free(decaps_times);

    return results;
}

// Benchmark for HQC-256 using a fresh keypair on every iteration
BenchmarkResults benchmark_hqc_fresh_keys(int iterations) {
    BenchmarkResults results = {0};

    results.pk_size = PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES;
    results.sk_size = PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES;
    results.ct_size = PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES;

    printf("\n--------------------------------------------------\n");
    printf("  HQC-256 (fresh keypair per iteration)\n");
    printf("--------------------------------------------------\n");
    printf("Iterations: %d (Warm-up: %d)\n", iterations, WARMUP_ITERATIONS);

    printf("Setting up benchmark environment...\n");
    set_cpu_affinity(0);
    set_high_priority();
    warmup_cpu();
    warmup_algorithm_hqc();

    double *keygen_times = malloc(iterations * sizeof(double));
    double *encaps_times = malloc(iterations * sizeof(double));
    double *decaps_times = malloc(iterations * sizeof(double));

    if (!keygen_times || !encaps_times || !decaps_times) {
        fprintf(stderr, "Error: Memory allocation failed for timing arrays\n");
        free(keygen_times);
        free(encaps_times);
        free(decaps_times);
        return results;
    }

    unsigned char *pk = malloc(results.pk_size);
    unsigned char *sk = malloc(results.sk_size);
    unsigned char *ct = malloc(results.ct_size);
    unsigned char ss_enc[PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES];
    unsigned char ss_dec[PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES];

    if (!pk || !sk || !ct) {
        fprintf(stderr, "Error: Memory allocation failed for main keys\n");
        free(pk); free(sk); free(ct);
        free(keygen_times); free(encaps_times); free(decaps_times);
        return results;
    }

    int failures = 0;

    printf("Benchmarking with a new keypair each iteration...\nProgress: ");
    fflush(stdout);

    for (int i = 0; i < iterations; i++) {
        if (i % 10 == 0) {
            printf(".");
            fflush(stdout);
        }

        double kg_start = get_time_ns();
        PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pk, sk);
        double kg_end = get_time_ns();
        keygen_times[i] = (kg_end - kg_start) / 1e6;

        double enc_start = get_time_ns();
        PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
        double enc_end = get_time_ns();
        encaps_times[i] = (enc_end - enc_start) / 1e6;

        double dec_start = get_time_ns();
        PQCLEAN_HQC256_CLEAN_crypto_kem_dec(ss_dec, ct, sk);
        double dec_end = get_time_ns();
        decaps_times[i] = (dec_end - dec_start) / 1e6;

        if (memcmp(ss_enc, ss_dec, PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES) != 0) {
            failures++;
        }
    }
    printf(" Done!\n");

    results.keygen_mean = calculate_mean(keygen_times, iterations);
    results.keygen_stddev = calculate_stddev(keygen_times, iterations, results.keygen_mean);

    results.encaps_mean = calculate_mean(encaps_times, iterations);
    results.encaps_stddev = calculate_stddev(encaps_times, iterations, results.encaps_mean);

    results.decaps_mean = calculate_mean(decaps_times, iterations);
    results.decaps_stddev = calculate_stddev(decaps_times, iterations, results.decaps_mean);

    results.peak_memory_kb = get_peak_memory_kb();

    if (failures == 0) {
        printf("* Correctness verification: SUCCESS (%d/%d matched)\n", iterations, iterations);
    } else {
        printf("* Correctness verification: FAILED (%d/%d mismatched)\n", failures, iterations);
    }

    free(pk); free(sk); free(ct);
    free(keygen_times); free(encaps_times); free(decaps_times);

    return results;
}



// ---- Helper: print a byte buffer in hex, truncated for readability ----
void print_hex_truncated(const char *label, const unsigned char *data, size_t len, size_t max_bytes) {
    printf("%s: ", label);
    size_t to_print = (len < max_bytes) ? len : max_bytes;
    for (size_t i = 0; i < to_print; i++) {
        printf("%02x", data[i]);
    }
    if (len > max_bytes) {
        printf("... (%zu bytes total)", len);
    }
    printf("\n");
}

// ---- Helper: min / max over an array of doubles ----
double calculate_min(double *values, int n) {
    double m = values[0];
    for (int i = 1; i < n; i++) if (values[i] < m) m = values[i];
    return m;
}

double calculate_max(double *values, int n) {
    double m = values[0];
    for (int i = 1; i < n; i++) if (values[i] > m) m = values[i];
    return m;
}

// ---- Struct for plaintext-variability results ----
typedef struct {
    double encaps_mean;
    double encaps_stddev;
    double encaps_min;
    double encaps_max;
    double decaps_mean;
    double decaps_stddev;
    double decaps_min;
    double decaps_max;
    int correctness_failures;
} PlaintextVariabilityResults;

// ---- McEliece: variability across different (randomly generated) shared secrets ----
PlaintextVariabilityResults benchmark_mceliece_plaintext_variability(int iterations, int print_secrets) {
    PlaintextVariabilityResults results = {0};

    size_t pk_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES;
    size_t sk_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES;
    size_t ct_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    size_t ss_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES;

    printf("\n--------------------------------------------------\n");
    printf("  McEliece6960119 - Plaintext (shared secret) variability\n");
    printf("--------------------------------------------------\n");
    printf("Fixed keypair, %d different plaintexts\n", iterations);

    set_cpu_affinity(0);
    set_high_priority();
    warmup_cpu();
    warmup_algorithm_mceliece();

    unsigned char *pk = malloc(pk_size);
    unsigned char *sk = malloc(sk_size);
    unsigned char *ct = malloc(ct_size);
    unsigned char *ss_enc = malloc(ss_size);
    unsigned char *ss_dec = malloc(ss_size);

    double *encaps_times = malloc(iterations * sizeof(double));
    double *decaps_times = malloc(iterations * sizeof(double));

    if (!pk || !sk || !ct || !ss_enc || !ss_dec || !encaps_times || !decaps_times) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
        free(encaps_times); free(decaps_times);
        return results;
    }

    // Fixed keypair for the whole test: only the plaintext (shared secret) changes
    PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pk, sk);

    printf("\n");
    for (int i = 0; i < iterations; i++) {
        double enc_start = get_time_ns();
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
        double enc_end = get_time_ns();
        encaps_times[i] = (enc_end - enc_start) / 1e6;

        double dec_start = get_time_ns();
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec(ss_dec, ct, sk);
        double dec_end = get_time_ns();
        decaps_times[i] = (dec_end - dec_start) / 1e6;

        if (memcmp(ss_enc, ss_dec, ss_size) != 0) {
            results.correctness_failures++;
        }

        if (print_secrets) {
            printf("Iter %2d | encaps: %7.3f ms | decaps: %7.3f ms | ", i, encaps_times[i], decaps_times[i]);
            print_hex_truncated("shared secret", ss_enc, ss_size, ss_size); // ss_size is small (32B), printed in full
        }
    }

    results.encaps_mean = calculate_mean(encaps_times, iterations);
    results.encaps_stddev = calculate_stddev(encaps_times, iterations, results.encaps_mean);
    results.encaps_min = calculate_min(encaps_times, iterations);
    results.encaps_max = calculate_max(encaps_times, iterations);

    results.decaps_mean = calculate_mean(decaps_times, iterations);
    results.decaps_stddev = calculate_stddev(decaps_times, iterations, results.decaps_mean);
    results.decaps_min = calculate_min(decaps_times, iterations);
    results.decaps_max = calculate_max(decaps_times, iterations);

    printf("\nSummary:\n");
    printf("\tEncaps: mean=%.3f ms  stddev=%.3f  min=%.3f  max=%.3f  (range=%.3f ms)\n",
           results.encaps_mean, results.encaps_stddev, results.encaps_min, results.encaps_max,
           results.encaps_max - results.encaps_min);
    printf("\tDecaps: mean=%.3f ms  stddev=%.3f  min=%.3f  max=%.3f  (range=%.3f ms)\n",
           results.decaps_mean, results.decaps_stddev, results.decaps_min, results.decaps_max,
           results.decaps_max - results.decaps_min);
    printf("\tCorrectness failures: %d/%d\n", results.correctness_failures, iterations);

    free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
    free(encaps_times); free(decaps_times);

    return results;
}

// ---- HQC-256: variability across different (randomly generated) shared secrets ----
PlaintextVariabilityResults benchmark_hqc_plaintext_variability(int iterations, int print_secrets) {
    PlaintextVariabilityResults results = {0};

    size_t pk_size = PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES;
    size_t sk_size = PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES;
    size_t ct_size = PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    size_t ss_size = PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES;

    printf("\n--------------------------------------------------\n");
    printf("  HQC-256 - Plaintext (shared secret) variability\n");
    printf("--------------------------------------------------\n");
    printf("Fixed keypair, %d different plaintexts\n", iterations);

    set_cpu_affinity(0);
    set_high_priority();
    warmup_cpu();
    warmup_algorithm_hqc();

    unsigned char *pk = malloc(pk_size);
    unsigned char *sk = malloc(sk_size);
    unsigned char *ct = malloc(ct_size);
    unsigned char *ss_enc = malloc(ss_size);
    unsigned char *ss_dec = malloc(ss_size);

    double *encaps_times = malloc(iterations * sizeof(double));
    double *decaps_times = malloc(iterations * sizeof(double));

    if (!pk || !sk || !ct || !ss_enc || !ss_dec || !encaps_times || !decaps_times) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
        free(encaps_times); free(decaps_times);
        return results;
    }

    PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pk, sk);

    printf("\n");
    for (int i = 0; i < iterations; i++) {
        double enc_start = get_time_ns();
        PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
        double enc_end = get_time_ns();
        encaps_times[i] = (enc_end - enc_start) / 1e6;

        double dec_start = get_time_ns();
        PQCLEAN_HQC256_CLEAN_crypto_kem_dec(ss_dec, ct, sk);
        double dec_end = get_time_ns();
        decaps_times[i] = (dec_end - dec_start) / 1e6;

        if (memcmp(ss_enc, ss_dec, ss_size) != 0) {
            results.correctness_failures++;
        }

        if (print_secrets) {
            printf("Iter %2d | encaps: %7.3f ms | decaps: %7.3f ms | ", i, encaps_times[i], decaps_times[i]);
            print_hex_truncated("shared secret", ss_enc, ss_size, ss_size);
        }
    }

    results.encaps_mean = calculate_mean(encaps_times, iterations);
    results.encaps_stddev = calculate_stddev(encaps_times, iterations, results.encaps_mean);
    results.encaps_min = calculate_min(encaps_times, iterations);
    results.encaps_max = calculate_max(encaps_times, iterations);

    results.decaps_mean = calculate_mean(decaps_times, iterations);
    results.decaps_stddev = calculate_stddev(decaps_times, iterations, results.decaps_mean);
    results.decaps_min = calculate_min(decaps_times, iterations);
    results.decaps_max = calculate_max(decaps_times, iterations);

    printf("\nSummary:\n");
    printf("\tEncaps: mean=%.3f ms  stddev=%.3f  min=%.3f  max=%.3f  (range=%.3f ms)\n",
           results.encaps_mean, results.encaps_stddev, results.encaps_min, results.encaps_max,
           results.encaps_max - results.encaps_min);
    printf("\tDecaps: mean=%.3f ms  stddev=%.3f  min=%.3f  max=%.3f  (range=%.3f ms)\n",
           results.decaps_mean, results.decaps_stddev, results.decaps_min, results.decaps_max,
           results.decaps_max - results.decaps_min);
    printf("\tCorrectness failures: %d/%d\n", results.correctness_failures, iterations);

    free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
    free(encaps_times); free(decaps_times);

    return results;
}
















void print_results(const char* name, BenchmarkResults results) {
    printf("\n==================================================\n");
    printf("  Detailed Results: %s\n", name);
    printf("==================================================\n");
    
    printf("\nSIZES:\n");
    printf("\tPublic key:\t%7zu bytes (%8.2f KB)\n", 
           results.pk_size, results.pk_size / 1024.0);
    printf("\tPrivate key:\t%7zu bytes (%8.2f KB)\n", 
           results.sk_size, results.sk_size / 1024.0);
    printf("\tCiphertext:\t%7zu bytes (%8.2f KB)\n", 
           results.ct_size, results.ct_size / 1024.0);
    printf("\tTotal keys:\t%7zu bytes (%8.2f KB)\n", 
           results.pk_size + results.sk_size, 
           (results.pk_size + results.sk_size) / 1024.0);
    
    printf("\nPERFORMANCE (mean +/- std dev):\n");
    printf("\tKey Generation:\t%8.3f +/- %6.3f ms\n", 
           results.keygen_mean, results.keygen_stddev);
    printf("\tEncapsulation:\t%8.3f +/- %6.3f ms\n", 
           results.encaps_mean, results.encaps_stddev);
    printf("\tDecapsulation:\t%8.3f +/- %6.3f ms\n", 
           results.decaps_mean, results.decaps_stddev);
    
    printf("\nVARIABILITY (Coefficient of Variation):\n");
    double keygen_cv = (results.keygen_stddev / results.keygen_mean) * 100;
    double encaps_cv = (results.encaps_stddev / results.encaps_mean) * 100;
    double decaps_cv = (results.decaps_stddev / results.decaps_mean) * 100;
    
    printf("\tKey Generation:\t%5.2f%% %s\n", 
           keygen_cv,
           keygen_cv < 5.0 ? "(very stable)" : 
           keygen_cv < 10.0 ? "(stable)" : "(variable)");
    printf("\tEncapsulation:\t%5.2f%% %s\n", 
           encaps_cv,
           encaps_cv < 5.0 ? "(very stable)" : 
           encaps_cv < 10.0 ? "(stable)" : "(variable)");
    printf("\tDecapsulation:\t%5.2f%% %s\n", 
           decaps_cv,
           decaps_cv < 5.0 ? "(very stable)" : 
           decaps_cv < 10.0 ? "(stable)" : "(variable)");
    
    printf("\nMEMORY:\n");
    printf("\tPeak usage:\t%7zu KB\n", results.peak_memory_kb);
    
    printf("\nTOTAL TIME (KeyGen + Encaps + Decaps):\n");
    printf("\tComplete operation:\t%.3f ms\n", 
           results.keygen_mean + results.encaps_mean + results.decaps_mean);
    
    printf("==================================================\n");
}

void print_comparison(BenchmarkResults mceliece, BenchmarkResults hqc) {
    printf("\n==================================================\n");
    printf("          DIRECT COMPARISON \n");
    printf("      McEliece6960119 vs HQC-256\n");
    printf("==================================================\n");
    
    printf("\nSECURITY LEVEL:\n");
    printf("\tBoth: NIST Level 5 (AES-256 equivalent)\n");
    
    printf("\nSIZE COMPARISON:\n");
    printf("\tPublic key:\n");
    printf("\t\tMcEliece:\t%7zu bytes (%.2f KB)\n", 
           mceliece.pk_size, mceliece.pk_size / 1024.0);
    printf("\t\tHQC:\t\t%7zu bytes (%.2f KB)\n", 
           hqc.pk_size, hqc.pk_size / 1024.0);

    double ratio;
    const char *bigger;

    if (mceliece.pk_size > hqc.pk_size) {
        ratio = (double)mceliece.pk_size / hqc.pk_size;
        bigger = "McEliece";
    } else {
        ratio = (double)hqc.pk_size / mceliece.pk_size;
        bigger = "HQC";
    }
    printf("\t\tRatio:\t\t%.2fx larger (%s is bigger)\n", ratio, bigger);
    
    printf("\tPrivate key:\n");
    printf("\t\tMcEliece:\t%7zu bytes (%.2f KB)\n", 
           mceliece.sk_size, mceliece.sk_size / 1024.0);
    printf("\t\tHQC:\t\t%7zu bytes (%.2f KB)\n", 
           hqc.sk_size, hqc.sk_size / 1024.0);

    if (mceliece.sk_size > hqc.sk_size) {
        ratio = (double)mceliece.sk_size / hqc.sk_size;
        bigger = "McEliece";
    } else {
        ratio = (double)hqc.sk_size / mceliece.sk_size;
        bigger = "HQC";
    }
    printf("\t\tRatio:\t\t%.2fx larger (%s is bigger)\n", ratio, bigger);
    
    printf("\tCiphertext:\n");
    printf("\t\tMcEliece:\t%7zu bytes (%.2f KB)\n", 
           mceliece.ct_size, mceliece.ct_size / 1024.0);
    printf("\t\tHQC:\t\t%7zu bytes (%.2f KB)\n", 
           hqc.ct_size, hqc.ct_size / 1024.0);

    if (mceliece.ct_size > hqc.ct_size) {
        ratio = (double)mceliece.ct_size / hqc.ct_size;
        bigger = "McEliece";
    } else {
        ratio = (double)hqc.ct_size / mceliece.ct_size;
        bigger = "HQC";
    }
    printf("\t\tRatio:\t\t%.2fx larger (%s is bigger)\n", ratio, bigger);
    
    printf("\nMEMORY:\n");
    printf("\tMcEliece peak:\t%7zu KB\n", mceliece.peak_memory_kb);
    printf("\tHQC peak:\t%7zu KB\n", hqc.peak_memory_kb);
    printf("\tDifference:\t%+ld KB\n", (long)(mceliece.peak_memory_kb - hqc.peak_memory_kb));
    
    // Calculate confidence intervals
    double mcg_keygen_ci = calculate_confidence_interval(mceliece.keygen_stddev, NUM_ITERATIONS);
    double mcg_encaps_ci = calculate_confidence_interval(mceliece.encaps_stddev, NUM_ITERATIONS);
    double mcg_decaps_ci = calculate_confidence_interval(mceliece.decaps_stddev, NUM_ITERATIONS);
    
    double hqc_keygen_ci = calculate_confidence_interval(hqc.keygen_stddev, NUM_ITERATIONS);
    double hqc_encaps_ci = calculate_confidence_interval(hqc.encaps_stddev, NUM_ITERATIONS);
    double hqc_decaps_ci = calculate_confidence_interval(hqc.decaps_stddev, NUM_ITERATIONS);
    
    printf("\nSPEED COMPARISON (with 95%% confidence intervals):\n");
    printf("\tKey Generation:\n");
    printf("\t\tMcEliece:\t%.3f +/- %.3f ms\n", 
           mceliece.keygen_mean, mcg_keygen_ci);
    printf("\t\tHQC:\t\t%.3f +/- %.3f ms\n", 
           hqc.keygen_mean, hqc_keygen_ci);

    const char *faster;

    if (mceliece.keygen_mean < hqc.keygen_mean) {
        ratio = (double)hqc.keygen_mean / mceliece.keygen_mean;
        faster = "McEliece";
    } else {
        ratio = (double)mceliece.keygen_mean / hqc.keygen_mean;
        faster = "HQC";
    }
    printf("\t\tRatio:\t\t%.2fx faster (%s is faster)\n", ratio, faster);
    
    printf("\tEncapsulation:\n");
    printf("\t\tMcEliece:\t%.3f +/- %.3f ms\n", 
           mceliece.encaps_mean, mcg_encaps_ci);
    printf("\t\tHQC:\t\t%.3f +/- %.3f ms\n", 
           hqc.encaps_mean, hqc_encaps_ci);

    if (mceliece.encaps_mean < hqc.encaps_mean) {
        ratio = (double)hqc.encaps_mean / mceliece.encaps_mean;
        faster = "McEliece";
    } else {
        ratio = (double)mceliece.encaps_mean / hqc.encaps_mean;
        faster = "HQC";
    }
    printf("\t\tRatio:\t\t%.2fx faster (%s is faster)\n", ratio, faster);
    
    printf("\tDecapsulation:\n");
    printf("\t\tMcEliece:\t%.3f +/- %.3f ms\n", 
           mceliece.decaps_mean, mcg_decaps_ci);
    printf("\t\tHQC:\t\t%.3f +/- %.3f ms\n", 
           hqc.decaps_mean, hqc_decaps_ci);

    if (mceliece.decaps_mean < hqc.decaps_mean) {
        ratio = (double)hqc.decaps_mean / mceliece.decaps_mean;
        faster = "McEliece";
    } else {
        ratio = (double)mceliece.decaps_mean / hqc.decaps_mean;
        faster = "HQC";
    }
    printf("\t\tRatio:\t\t%.2fx faster (%s is faster)\n", ratio, faster);
    
    double mceliece_total = mceliece.keygen_mean + mceliece.encaps_mean + mceliece.decaps_mean;
    double hqc_total = hqc.keygen_mean + hqc.encaps_mean + hqc.decaps_mean;
    double mcg_total_ci = sqrt(mcg_keygen_ci*mcg_keygen_ci + mcg_encaps_ci*mcg_encaps_ci + mcg_decaps_ci*mcg_decaps_ci);
    double hqc_total_ci = sqrt(hqc_keygen_ci*hqc_keygen_ci + hqc_encaps_ci*hqc_encaps_ci + hqc_decaps_ci*hqc_decaps_ci);
    
    printf("\nTOTAL TIME:\n");
    printf("\tMcEliece:\t%.3f +/- %.3f ms\n", mceliece_total, mcg_total_ci);
    printf("\tHQC:\t\t%.3f +/- %.3f ms\n", hqc_total, hqc_total_ci);
    
    double diff = mceliece_total - hqc_total;
    double diff_ci = sqrt(mcg_total_ci*mcg_total_ci + hqc_total_ci*hqc_total_ci);
    double percent_diff = fabs(diff) / ((mceliece_total + hqc_total) / 2) * 100;
    
    printf("\tDifference:\t%.3f +/- %.3f ms (%.1f%% %s)\n", 
           diff, diff_ci, percent_diff,
           diff > 0 ? "(HQC faster)" : "(McEliece faster)");
    
    // Statistical significance test
    printf("\nSTATISTICAL SIGNIFICANCE:\n");
    double keygen_combined_ci = sqrt(mcg_keygen_ci*mcg_keygen_ci + hqc_keygen_ci*hqc_keygen_ci);
    double encaps_combined_ci = sqrt(mcg_encaps_ci*mcg_encaps_ci + hqc_encaps_ci*hqc_encaps_ci);
    double decaps_combined_ci = sqrt(mcg_decaps_ci*mcg_decaps_ci + hqc_decaps_ci*hqc_decaps_ci);
    
    printf("\tKeyGen difference significant?\t%s (%.2f sigma)\n",
           fabs(mceliece.keygen_mean - hqc.keygen_mean) > keygen_combined_ci ? "YES" : "NO",
           fabs(mceliece.keygen_mean - hqc.keygen_mean) / keygen_combined_ci);
    printf("\tEncaps difference significant?\t%s (%.2f sigma)\n",
           fabs(mceliece.encaps_mean - hqc.encaps_mean) > encaps_combined_ci ? "YES" : "NO",
           fabs(mceliece.encaps_mean - hqc.encaps_mean) / encaps_combined_ci);
    printf("\tDecaps difference significant?\t%s (%.2f sigma)\n",
           fabs(mceliece.decaps_mean - hqc.decaps_mean) > decaps_combined_ci ? "YES" : "NO",
           fabs(mceliece.decaps_mean - hqc.decaps_mean) / decaps_combined_ci);
    
    double mceliece_cv = ((mceliece.keygen_stddev / mceliece.keygen_mean) + 
                          (mceliece.encaps_stddev / mceliece.encaps_mean) + 
                          (mceliece.decaps_stddev / mceliece.decaps_mean)) / 3 * 100;
    double hqc_cv = ((hqc.keygen_stddev / hqc.keygen_mean) + 
                     (hqc.encaps_stddev / hqc.encaps_mean) + 
                     (hqc.decaps_stddev / hqc.decaps_mean)) / 3 * 100;
    
    printf("\nSTABILITY:\n");
    printf("\tMcEliece average CV:\t%.2f%%\n", mceliece_cv);
    printf("\tHQC average CV:\t\t%.2f%%\n", hqc_cv);
    printf("\tMore stable:\t\t%s\n", 
           mceliece_cv < hqc_cv ? "McEliece" : "HQC");
    
    double mceliece_size_total = mceliece.pk_size + mceliece.sk_size;
    double hqc_size_total = hqc.pk_size + hqc.sk_size;
    
    printf("\nSUMMARY:\n");
    printf("\t* Smaller keys:\t\t%s\n", 
           mceliece_size_total < hqc_size_total ? "McEliece" : "HQC");
    printf("\t* Faster:\t\t%s\n", 
           mceliece_total < hqc_total ? "McEliece" : "HQC");
    printf("\t* Less memory:\t\t%s\n", 
           mceliece.peak_memory_kb < hqc.peak_memory_kb ? "McEliece" : "HQC");
    printf("\t* More stable:\t\t%s\n", 
           mceliece_cv < hqc_cv ? "McEliece" : "HQC");
    printf("\t* Security:\t\tEQUIVALENT (both Level 5)\n");

    
    printf("\n==================================================\n");
}

int main() {
    printf("\n");
    printf("==================================================\n");
    printf("                                                  \n");
    printf("    POST-QUANTUM CRYPTOGRAPHY BENCHMARK          \n");
    printf("    McEliece6960119 vs HQC-256                   \n");
    printf("                                                  \n");
    printf("    Library: PQClean                             \n");
    printf("    Precision: nanosecond timing                 \n");
    printf("    Statistics: %3d iterations, 95%% CI          \n", NUM_ITERATIONS);
    printf("                                                  \n");
    printf("==================================================\n");
    
    printf("\nConfiguration:\n");
    printf("\t* Iterations per test:\t%d\n", NUM_ITERATIONS);
    printf("\t* Warm-up iterations:\t%d\n", WARMUP_ITERATIONS);
    printf("\t* Timing precision:\tnanosecond (CLOCK_MONOTONIC_RAW)\n");
    printf("\t* CPU affinity:\t\tenabled (core 0)\n");
    printf("\t* Process priority:\thigh (requires root for full effect)\n");
    printf("\t* Memory tracking:\tenabled\n");
    

    
    //BenchmarkResults mceliece_results = benchmark_mceliece(NUM_ITERATIONS);
    //BenchmarkResults hqc_results = benchmark_hqc(NUM_ITERATIONS);

    BenchmarkResults mceliece_results = run_isolated(benchmark_mceliece, NUM_ITERATIONS);
    BenchmarkResults hqc_results = run_isolated(benchmark_hqc, NUM_ITERATIONS);
    
    print_results("McEliece6960119", mceliece_results);
    print_results("HQC-256", hqc_results);
    print_comparison(mceliece_results, hqc_results);
    

/*
    BenchmarkResults mceliece_fresh = benchmark_mceliece_fresh_keys(NUM_ITERATIONS);
    BenchmarkResults hqc_fresh = benchmark_hqc_fresh_keys(NUM_ITERATIONS);

    print_results("McEliece6960119 (fresh keys)", mceliece_fresh);
    print_results("HQC-256 (fresh keys)", hqc_fresh);
    print_comparison(mceliece_fresh, hqc_fresh);
*/
    
// ./benchmark_mceliece_hqc > results_$(date +%Y%m%d_%H%M%S).txt

    
    return 0;
}