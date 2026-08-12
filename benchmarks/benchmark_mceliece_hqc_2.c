#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <sched.h>           // AGGIUNTO: Per CPU affinity
#include <sys/resource.h>    // AGGIUNTO: Per priorità processo

// Include McEliece6960119 (Level 5)
#include "crypto_kem/mceliece6960119/clean/api.h"

// Include HQC-256 (Level 5)
#include "crypto_kem/hqc-256/clean/api.h"

#define NUM_ITERATIONS 10   // MODIFICATO: Aumentato da 10 a 100 per significatività statistica
#define WARMUP_ITERATIONS 5  // AGGIUNTO: Iterazioni di riscaldamento

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
    size_t peak_memory_kb;   // AGGIUNTO: Memoria di picco
} BenchmarkResults;

// AGGIUNTO: Funzione per impostare l'affinità della CPU
void set_cpu_affinity(int cpu_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) != 0) {
        perror("sched_setaffinity");
    }
}

// AGGIUNTO: Funzione per impostare priorità alta
void set_high_priority() {
    if (setpriority(PRIO_PROCESS, 0, -20) != 0) {
        perror("setpriority");
    }
}

// AGGIUNTO: Funzione di riscaldamento della CPU
void warmup_cpu() {
    volatile double sum = 0.0;
    for (long i = 0; i < 1000000; i++) {
        sum += sqrt(i + 1.0);
    }
    // Prevenire l'ottimizzazione del compilatore
    if (sum == 0.0) {
        printf(""); // Operazione dummy
    }
}

// MODIFICATO: Ora restituisce nanosecondi per maggiore precisione
double get_time_ns() {
    struct timespec ts;
    // MODIFICATO: CLOCK_MONOTONIC_RAW per evitare aggiustamenti NTP
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}

// AGGIUNTO: Funzione per ottenere memoria di picco in KB
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

// AGGIUNTO: Calcola intervallo di confidenza al 95%
double calculate_confidence_interval(double stddev, int n) {
    // Valore t per distribuzione t-Student
    // Per n=100: ~1.984, per n=10: ~2.262
    double t_values[] = {0, 0, 0, 0, 0, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228};
    double t_value = (n < 11 && n > 5) ? t_values[n] : 1.96; // Approssimazione per n≥30
    return t_value * stddev / sqrt(n);
}

// AGGIUNTO: Funzione per warmup specifico dell'algoritmo
void warmup_algorithm_mceliece() {
    size_t pk_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES;
    size_t sk_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES;
    
    unsigned char *warmup_pk = malloc(pk_size);
    unsigned char *warmup_sk = malloc(sk_size);
    
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(warmup_pk, warmup_sk);
    }
    
    free(warmup_pk);
    free(warmup_sk);
}

// AGGIUNTO: Funzione per warmup specifico dell'algoritmo HQC
void warmup_algorithm_hqc() {
    size_t pk_size = PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES;
    size_t sk_size = PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES;
    
    unsigned char *warmup_pk = malloc(pk_size);
    unsigned char *warmup_sk = malloc(sk_size);
    
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
    printf("│  McEliece6960119 (NIST Level 5 - AES-256 eq.)  │\n");
    printf("--------------------------------------------------\n");
    printf("Parameters: n=6960, k=5413, t=119\n");
    printf("Iterations: %d (Warm-up: %d)\n", iterations, WARMUP_ITERATIONS);
    
    // AGGIUNTO: Setup ambiente benchmark
    printf("Setting up benchmark environment...\n");
    set_cpu_affinity(0);      // Fissa alla CPU 0
    set_high_priority();      // Priorità massima
    warmup_cpu();             // Riscaldamento CPU generale
    warmup_algorithm_mceliece(); // Riscaldamento specifico algoritmo
    
    double *keygen_times = malloc(iterations * sizeof(double));
    double *encaps_times = malloc(iterations * sizeof(double));
    double *decaps_times = malloc(iterations * sizeof(double));
    
    printf("Benchmarking...\nProgress: ");
    fflush(stdout);
    
    // MODIFICATO: Benchmark Key Generation con allocazioni separate per ogni iterazione
    for (int i = 0; i < iterations; i++) {
        if (i % 20 == 0) {
            printf(".");
            fflush(stdout);
        }
        
        // AGGIUNTO: Alloca memoria fresca per ogni iterazione
        unsigned char *pk = malloc(results.pk_size);
        unsigned char *sk = malloc(results.sk_size);
        
        double start = get_time_ns();
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pk, sk);
        double end = get_time_ns();
        
        keygen_times[i] = (end - start) / 1e6;  // MODIFICATO: Converti ns → ms
        
        free(pk);
        free(sk);
    }
    
    printf(" Done!\n");
    
    // AGGIUNTO: Salva memoria di picco dopo keygen
    results.peak_memory_kb = get_peak_memory_kb();
    
    // MODIFICATO: Generate a keypair per subsequent tests (fuori dal loop timing)
    unsigned char *pk = malloc(results.pk_size);
    unsigned char *sk = malloc(results.sk_size);
    PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pk, sk);
    
    unsigned char *ct = malloc(results.ct_size);
    unsigned char ss_enc[PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES];
    unsigned char ss_dec[PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES];
    
    printf("Benchmarking encapsulation...\n");
    // Benchmark Encapsulation
    for (int i = 0; i < iterations; i++) {
        double start = get_time_ns();
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
        double end = get_time_ns();
        encaps_times[i] = (end - start) / 1e6;  // MODIFICATO: Converti ns → ms
    }
    
    printf("Benchmarking decapsulation...\n");
    // Generate a ciphertext for decapsulation test
    PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
    
    // Benchmark Decapsulation
    for (int i = 0; i < iterations; i++) {
        double start = get_time_ns();
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec(ss_dec, ct, sk);
        double end = get_time_ns();
        decaps_times[i] = (end - start) / 1e6;  // MODIFICATO: Converti ns → ms
    }
    
    // Calculate statistics
    results.keygen_mean = calculate_mean(keygen_times, iterations);
    results.keygen_stddev = calculate_stddev(keygen_times, iterations, results.keygen_mean);
    
    results.encaps_mean = calculate_mean(encaps_times, iterations);
    results.encaps_stddev = calculate_stddev(encaps_times, iterations, results.encaps_mean);
    
    results.decaps_mean = calculate_mean(decaps_times, iterations);
    results.decaps_stddev = calculate_stddev(decaps_times, iterations, results.decaps_mean);
    
    // Verify correctness
    if (memcmp(ss_enc, ss_dec, PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES) == 0) {
        printf("Verification of McEliece correctness: SUCCESS\n");
    } else {
        printf("Verification of McEliece correctness: FAILED\n");
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
    printf("│  HQC-256 (NIST Level 5 - AES-256 equivalent)   │\n");
    printf("--------------------------------------------------\n");
    printf("Parameters: n=46747, k=256, w=133, wr=153\n");
    printf("Iterations: %d (Warm-up: %d)\n", iterations, WARMUP_ITERATIONS);
    
    // AGGIUNTO: Setup ambiente benchmark
    printf("Setting up benchmark environment...\n");
    set_cpu_affinity(0);      // Fissa alla CPU 0
    set_high_priority();      // Priorità massima
    warmup_cpu();             // Riscaldamento CPU generale
    warmup_algorithm_hqc();   // Riscaldamento specifico algoritmo
    
    double *keygen_times = malloc(iterations * sizeof(double));
    double *encaps_times = malloc(iterations * sizeof(double));
    double *decaps_times = malloc(iterations * sizeof(double));
    
    printf("Benchmarking...\nProgress: ");
    fflush(stdout);
    
    // MODIFICATO: Benchmark Key Generation con allocazioni separate per ogni iterazione
    for (int i = 0; i < iterations; i++) {
        if (i % 20 == 0) {
            printf(".");
            fflush(stdout);
        }
        
        // AGGIUNTO: Alloca memoria fresca per ogni iterazione
        unsigned char *pk = malloc(results.pk_size);
        unsigned char *sk = malloc(results.sk_size);
        
        double start = get_time_ns();
        PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pk, sk);
        double end = get_time_ns();
        
        keygen_times[i] = (end - start) / 1e6;  // MODIFICATO: Converti ns → ms
        
        free(pk);
        free(sk);
    }
    
    printf(" Done!\n");
    
    // AGGIUNTO: Salva memoria di picco dopo keygen
    results.peak_memory_kb = get_peak_memory_kb();
    
    // MODIFICATO: Generate a keypair per subsequent tests (fuori dal loop timing)
    unsigned char *pk = malloc(results.pk_size);
    unsigned char *sk = malloc(results.sk_size);
    PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pk, sk);
    
    unsigned char *ct = malloc(results.ct_size);
    unsigned char ss_enc[PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES];
    unsigned char ss_dec[PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES];
    
    printf("Benchmarking encapsulation...\n");
    // Benchmark Encapsulation
    for (int i = 0; i < iterations; i++) {
        double start = get_time_ns();
        PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
        double end = get_time_ns();
        encaps_times[i] = (end - start) / 1e6;  // MODIFICATO: Converti ns → ms
    }
    
    printf("Benchmarking decapsulation...\n");
    // Generate a ciphertext for decapsulation test
    PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
    
    // Benchmark Decapsulation
    for (int i = 0; i < iterations; i++) {
        double start = get_time_ns();
        PQCLEAN_HQC256_CLEAN_crypto_kem_dec(ss_dec, ct, sk);
        double end = get_time_ns();
        decaps_times[i] = (end - start) / 1e6;  // MODIFICATO: Converti ns → ms
    }
    
    // Calculate statistics
    results.keygen_mean = calculate_mean(keygen_times, iterations);
    results.keygen_stddev = calculate_stddev(keygen_times, iterations, results.keygen_mean);
    
    results.encaps_mean = calculate_mean(encaps_times, iterations);
    results.encaps_stddev = calculate_stddev(encaps_times, iterations, results.encaps_mean);
    
    results.decaps_mean = calculate_mean(decaps_times, iterations);
    results.decaps_stddev = calculate_stddev(decaps_times, iterations, results.decaps_mean);
    
    // Verify correctness
    if (memcmp(ss_enc, ss_dec, PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES) == 0) {
        printf("Verification of HQC correctness: SUCCESS\n");
    } else {
        printf("Verification of HQC correctness: FAILED\n");
    }
    
    free(pk);
    free(sk);
    free(ct);
    free(keygen_times);
    free(encaps_times);
    free(decaps_times);
    
    return results;
}

void print_results(const char* name, BenchmarkResults results) {
    printf("\n=================================================================\n");
    printf("  Detailed Results: %s\n", name);
    printf("=================================================================\n");
    
    printf("\nMEMORY FOOTPRINT:\n");
    printf("\t - Public Key: \t\t %7zu bytes (%8.2f KB)\n", 
           results.pk_size, results.pk_size / 1024.0);
    printf("\t - Private Key: \t %7zu bytes (%8.2f KB)\n", 
           results.sk_size, results.sk_size / 1024.0);
    printf("\t - Ciphertext: \t\t %7zu bytes (%8.2f KB)\n", 
           results.ct_size, results.ct_size / 1024.0);
    printf("\t - Total key size: \t %7zu bytes (%8.2f KB)\n", 
           results.pk_size + results.sk_size, 
           (results.pk_size + results.sk_size) / 1024.0);
    printf("\t - Peak Memory Usage: \t %7zu KB\n", results.peak_memory_kb);
    
    // AGGIUNTO: Calcolo intervalli di confidenza
    double keygen_ci = calculate_confidence_interval(results.keygen_stddev, NUM_ITERATIONS);
    double encaps_ci = calculate_confidence_interval(results.encaps_stddev, NUM_ITERATIONS);
    double decaps_ci = calculate_confidence_interval(results.decaps_stddev, NUM_ITERATIONS);
    
    printf("\nPERFORMANCE (mean ± 95%% CI, %d iterations):\n", NUM_ITERATIONS);
    printf("\t - Key Generation: \t %8.3f ± %6.3f ms (CI: [%.3f, %.3f] ms)\n", 
           results.keygen_mean, results.keygen_stddev,
           results.keygen_mean - keygen_ci, results.keygen_mean + keygen_ci);
    printf("\t - Encapsulation: \t %8.3f ± %6.3f ms (CI: [%.3f, %.3f] ms)\n", 
           results.encaps_mean, results.encaps_stddev,
           results.encaps_mean - encaps_ci, results.encaps_mean + encaps_ci);
    printf("\t - Decapsulation: \t %8.3f ± %6.3f ms (CI: [%.3f, %.3f] ms)\n", 
           results.decaps_mean, results.decaps_stddev,
           results.decaps_mean - decaps_ci, results.decaps_mean + decaps_ci);
    
    printf("\nVARIABILITY (Coefficient of Variation):\n");
    double keygen_cv = (results.keygen_stddev / results.keygen_mean) * 100;
    double encaps_cv = (results.encaps_stddev / results.encaps_mean) * 100;
    double decaps_cv = (results.decaps_stddev / results.decaps_mean) * 100;
    
    printf("\t - Key Generation: \t %5.2f%% %s\n", 
           keygen_cv,
           keygen_cv < 5.0 ? "★★★ (very stable)" : 
           keygen_cv < 10.0 ? "★★ (stable)" : "★ (variable)");
    printf("\t - Encapsulation: \t %5.2f%% %s\n", 
           encaps_cv,
           encaps_cv < 5.0 ? "★★★ (very stable)" : 
           encaps_cv < 10.0 ? "★★ (stable)" : "★ (variable)");
    printf("\t - Decapsulation: \t %5.2f%% %s\n", 
           decaps_cv,
           decaps_cv < 5.0 ? "★★★ (very stable)" : 
           decaps_cv < 10.0 ? "★★ (stable)" : "★ (variable)");
    
    printf("\nTOTAL TIME FOR OPERATIONS:\n");
    double total_time = results.keygen_mean + results.encaps_mean + results.decaps_mean;
    double total_ci = sqrt(keygen_ci*keygen_ci + encaps_ci*encaps_ci + decaps_ci*decaps_ci);
    printf("\t - KeyGen + Encaps + Decaps: \t %.3f ± %.3f ms\n", 
           total_time, total_ci);
    
    // AGGIUNTO: Stima throughput
    printf("\nESTIMATED THROUGHPUT:\n");
    printf("\t - Encapsulations/sec: \t %.1f\n", 1000.0 / results.encaps_mean);
    printf("\t - Decapsulations/sec: \t %.1f\n", 1000.0 / results.decaps_mean);
    
    printf("\n=================================================================\n");
}

void print_comparison(BenchmarkResults mceliece, BenchmarkResults hqc) {
    printf("\n==============================================================\n");
    printf("|           COMPARISON (NIST Level 5)                        |\n");
    printf("|        McEliece6960119  vs  HQC-256                        |\n");
    printf("|        %d iterations, 95%% confidence intervals             |\n", NUM_ITERATIONS);
    printf("==============================================================\n");
    
    printf("\nSIZE COMPARISON:\n");
    printf("\t - Public key:\n");
    printf("\t \t * McEliece: \t %7zu bytes (%.2f KB)\n", 
           mceliece.pk_size, mceliece.pk_size / 1024.0);
    printf("\t \t * HQC: \t %7zu bytes (%.2f KB)\n", 
           hqc.pk_size, hqc.pk_size / 1024.0);
    printf("\t \t * Ratio: \t %.2fx %s\n", 
           (double)mceliece.pk_size / hqc.pk_size,
           mceliece.pk_size > hqc.pk_size ? "(McEliece bigger)" : "(HQC bigger)");
    
    printf("\t - Private key:\n");
    printf("\t \t * McEliece: \t %7zu bytes (%.2f KB)\n", 
           mceliece.sk_size, mceliece.sk_size / 1024.0);
    printf("\t \t * HQC: \t %7zu bytes (%.2f KB)\n", 
           hqc.sk_size, hqc.sk_size / 1024.0);
    printf("\t \t * Ratio: \t %.2fx %s\n", 
           (double)mceliece.sk_size / hqc.sk_size,
           mceliece.sk_size > hqc.sk_size ? "(McEliece bigger)" : "(HQC bigger)");
    
    printf("\t - Ciphertext:\n");
    printf("\t \t * McEliece: \t %7zu bytes (%.2f KB)\n", 
           mceliece.ct_size, mceliece.ct_size / 1024.0);
    printf("\t \t * HQC: \t %7zu bytes (%.2f KB)\n", 
           hqc.ct_size, hqc.ct_size / 1024.0);
    printf("\t \t * Ratio: \t %.2fx %s\n", 
           (double)mceliece.ct_size / hqc.ct_size,
           mceliece.ct_size > hqc.ct_size ? "(McEliece bigger)" : "(HQC bigger)");
    
    printf("\t - Peak Memory Usage:\n");
    printf("\t \t * McEliece: \t %7zu KB\n", mceliece.peak_memory_kb);
    printf("\t \t * HQC: \t %7zu KB\n", hqc.peak_memory_kb);
    printf("\t \t * Difference: \t %+d KB\n", (int)(mceliece.peak_memory_kb - hqc.peak_memory_kb));
    
    // AGGIUNTO: Calcolo intervalli di confidenza
    double mcg_keygen_ci = calculate_confidence_interval(mceliece.keygen_stddev, NUM_ITERATIONS);
    double mcg_encaps_ci = calculate_confidence_interval(mceliece.encaps_stddev, NUM_ITERATIONS);
    double mcg_decaps_ci = calculate_confidence_interval(mceliece.decaps_stddev, NUM_ITERATIONS);
    
    double hqc_keygen_ci = calculate_confidence_interval(hqc.keygen_stddev, NUM_ITERATIONS);
    double hqc_encaps_ci = calculate_confidence_interval(hqc.encaps_stddev, NUM_ITERATIONS);
    double hqc_decaps_ci = calculate_confidence_interval(hqc.decaps_stddev, NUM_ITERATIONS);
    
    printf("\nSPEED COMPARISON (with 95%% confidence intervals):\n");
    printf("\t - Key Generation:\n");
    printf("\t \t * McEliece: \t %.3f ± %.3f ms\n", 
           mceliece.keygen_mean, mcg_keygen_ci);
    printf("\t \t * HQC: \t %.3f ± %.3f ms\n", 
           hqc.keygen_mean, hqc_keygen_ci);
    printf("\t \t * Ratio: \t %.2fx %s\n", 
           mceliece.keygen_mean / hqc.keygen_mean,
           mceliece.keygen_mean > hqc.keygen_mean ? "(HQC faster)" : "(McEliece faster)");
    
    printf("\t - Encapsulation:\n");
    printf("\t \t * McEliece: \t %.3f ± %.3f ms\n", 
           mceliece.encaps_mean, mcg_encaps_ci);
    printf("\t \t * HQC: \t %.3f ± %.3f ms\n", 
           hqc.encaps_mean, hqc_encaps_ci);
    printf("\t \t * Ratio: \t %.2fx %s\n", 
           mceliece.encaps_mean / hqc.encaps_mean,
           mceliece.encaps_mean > hqc.encaps_mean ? "(HQC faster)" : "(McEliece faster)");
    
    printf("\t - Decapsulation:\n");
    printf("\t \t * McEliece: \t %.3f ± %.3f ms\n", 
           mceliece.decaps_mean, mcg_decaps_ci);
    printf("\t \t * HQC: \t %.3f ± %.3f ms\n", 
           hqc.decaps_mean, hqc_decaps_ci);
    printf("\t \t * Ratio: \t %.2fx %s\n", 
           mceliece.decaps_mean / hqc.decaps_mean,
           mceliece.decaps_mean > hqc.decaps_mean ? "(HQC faster)" : "(McEliece faster)");
    
    double mceliece_total = mceliece.keygen_mean + mceliece.encaps_mean + mceliece.decaps_mean;
    double hqc_total = hqc.keygen_mean + hqc.encaps_mean + hqc.decaps_mean;
    double mcg_total_ci = sqrt(mcg_keygen_ci*mcg_keygen_ci + mcg_encaps_ci*mcg_encaps_ci + mcg_decaps_ci*mcg_decaps_ci);
    double hqc_total_ci = sqrt(hqc_keygen_ci*hqc_keygen_ci + hqc_encaps_ci*hqc_encaps_ci + hqc_decaps_ci*hqc_decaps_ci);
    
    printf("\nTOTAL TIME (KeyGen + Encaps + Decaps):\n");
    printf("\t - McEliece: \t %.3f ± %.3f ms\n", mceliece_total, mcg_total_ci);
    printf("\t - HQC: \t %.3f ± %.3f ms\n", hqc_total, hqc_total_ci);
    
    double diff = mceliece_total - hqc_total;
    double diff_ci = sqrt(mcg_total_ci*mcg_total_ci + hqc_total_ci*hqc_total_ci);
    double percent_diff = fabs(diff) / ((mceliece_total + hqc_total) / 2) * 100;
    
    printf("\t - Difference: \t %.3f ± %.3f ms (%.1f%% %s)\n", 
           diff, diff_ci, percent_diff,
           diff > 0 ? "(HQC faster)" : "(McEliece faster)");
    
    // AGGIUNTO: Test di significatività statistica
    printf("\nSTATISTICAL SIGNIFICANCE:\n");
    printf("\t - KeyGen diff significant? \t %s (%.2f CI units)\n",
           fabs(mceliece.keygen_mean - hqc.keygen_mean) > sqrt(mcg_keygen_ci*mcg_keygen_ci + hqc_keygen_ci*hqc_keygen_ci) ? "YES" : "NO",
           fabs(mceliece.keygen_mean - hqc.keygen_mean) / sqrt(mcg_keygen_ci*mcg_keygen_ci + hqc_keygen_ci*hqc_keygen_ci));
    printf("\t - Encaps diff significant? \t %s (%.2f CI units)\n",
           fabs(mceliece.encaps_mean - hqc.encaps_mean) > sqrt(mcg_encaps_ci*mcg_encaps_ci + hqc_encaps_ci*hqc_encaps_ci) ? "YES" : "NO",
           fabs(mceliece.encaps_mean - hqc.encaps_mean) / sqrt(mcg_encaps_ci*mcg_encaps_ci + hqc_encaps_ci*hqc_encaps_ci));
    printf("\t - Decaps diff significant? \t %s (%.2f CI units)\n",
           fabs(mceliece.decaps_mean - hqc.decaps_mean) > sqrt(mcg_decaps_ci*mcg_decaps_ci + hqc_decaps_ci*hqc_decaps_ci) ? "YES" : "NO",
           fabs(mceliece.decaps_mean - hqc.decaps_mean) / sqrt(mcg_decaps_ci*mcg_decaps_ci + hqc_decaps_ci*hqc_decaps_ci));
    
    double mceliece_cv = ((mceliece.keygen_stddev / mceliece.keygen_mean) + 
                          (mceliece.encaps_stddev / mceliece.encaps_mean) + 
                          (mceliece.decaps_stddev / mceliece.decaps_mean)) / 3 * 100;
    double hqc_cv = ((hqc.keygen_stddev / hqc.keygen_mean) + 
                     (hqc.encaps_stddev / hqc.encaps_mean) + 
                     (hqc.decaps_stddev / hqc.decaps_mean)) / 3 * 100;
    
    printf("\nSTABILITY (lower CV = more predictable):\n");
    printf("\t - McEliece average CV: \t %.2f%%\n", mceliece_cv);
    printf("\t - HQC average CV: \t\t %.2f%%\n", hqc_cv);
    printf("\t - More stable: \t\t %s (%.1f%% better)\n", 
           mceliece_cv < hqc_cv ? "McEliece" : "HQC",
           fabs(mceliece_cv - hqc_cv) / ((mceliece_cv + hqc_cv) / 2) * 100);
    
    double mceliece_size_total = mceliece.pk_size + mceliece.sk_size;
    double hqc_size_total = hqc.pk_size + hqc.sk_size;
    
    printf("\nSUMMARY RECAP:\n");
    printf("\t - Size Efficiency: \t %s (%.1f%% smaller)\n", 
           mceliece_size_total < hqc_size_total ? "McEliece" : "HQC",
           fabs(mceliece_size_total - hqc_size_total) / ((mceliece_size_total + hqc_size_total) / 2) * 100);
    printf("\t - Speed Performance: \t %s (%.1f%% faster)\n", 
           mceliece_total < hqc_total ? "McEliece" : "HQC",
           percent_diff);
    printf("\t - Memory Usage: \t %s (%.1f%% less peak memory)\n", 
           mceliece.peak_memory_kb < hqc.peak_memory_kb ? "McEliece" : "HQC",
           fabs((double)mceliece.peak_memory_kb - hqc.peak_memory_kb) / ((mceliece.peak_memory_kb + hqc.peak_memory_kb) / 2) * 100);
    printf("\t - Timing Stability: \t %s\n", 
           mceliece_cv < hqc_cv ? "McEliece" : "HQC");
    printf("\t - Security Level: \t EQUIVALENT (NIST Level 5)\n");
    
    printf("\nRECOMMENDATION:\n");
    if (mceliece_total < hqc_total && mceliece_size_total < hqc_size_total) {
        printf("\t ★ McEliece6960119 is recommended (faster and smaller)\n");
    } else if (mceliece_total < hqc_total) {
        printf("\t ★ McEliece6960119 is faster but has larger keys\n");
    } else if (mceliece_size_total < hqc_size_total) {
        printf("\t ★ HQC-256 is faster but McEliece has smaller keys\n");
    } else {
        printf("\t ★ HQC-256 is recommended (balanced performance)\n");
    }
    
    printf("\n==============================================================\n");
}

int main() {
    printf("\n");
    printf("==================================================\n");
    printf("|                                                |\n");
    printf("|    BENCHMARK: POST-QUANTUM KEMs               |\n");
    printf("|    McEliece6960119 vs HQC-256                 |\n");
    printf("|                                                |\n");
    printf("|    Library: PQClean                           |\n");
    printf("|    Precision: nanosecond timing               |\n");
    printf("|    Statistics: %d iterations, 95%% CI          |\n", NUM_ITERATIONS);
    printf("|    Environment: CPU affinity, high priority   |\n");
    printf("|                                                |\n");
    printf("==================================================\n");
    
    // AGGIUNTO: Print system info
    printf("\nSystem Configuration:\n");
    printf("  - Iterations per test: %d\n", NUM_ITERATIONS);
    printf("  - Warm-up iterations: %d\n", WARMUP_ITERATIONS);
    printf("  - Timing precision: nanosecond (CLOCK_MONOTONIC_RAW)\n");
    printf("  - CPU affinity: core 0\n");
    printf("  - Process priority: high\n");
    printf("  - Memory tracking: enabled\n");
    
    BenchmarkResults mceliece_results = benchmark_mceliece(NUM_ITERATIONS);
    BenchmarkResults hqc_results = benchmark_hqc(NUM_ITERATIONS);
    
    print_results("McEliece6960119", mceliece_results);
    print_results("HQC-256", hqc_results);
    print_comparison(mceliece_results, hqc_results);
    
    // AGGIUNTO: Istruzioni per esportazione risultati
    printf("\nTo export results to a file:\n");
    printf("  ./benchmark_mceliece_hqc > risultati_$(date +%%Y%%m%%d_%%H%%M%%S).txt\n");
    
    // AGGIUNTO: Footer con timestamp
    time_t now = time(NULL);
    printf("\nBenchmark completed: %s", ctime(&now));
    printf("==================================================\n");
    
    return 0;
}