#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

// Include McEliece6960119 (Level 5)
#include "crypto_kem/mceliece6960119/clean/api.h"

// Include HQC-256 (Level 5)
#include "crypto_kem/hqc-256/clean/api.h"

#define NUM_ITERATIONS 10

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
} BenchmarkResults;

// Function to measure time in milliseconds
double get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
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

// Benchmark for McEliece
BenchmarkResults benchmark_mceliece(int iterations) {
    BenchmarkResults results = {0};
    
    results.pk_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES;
    results.sk_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES;
    results.ct_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    
    unsigned char *pk = malloc(results.pk_size);
    unsigned char *sk = malloc(results.sk_size);
    unsigned char *ct = malloc(results.ct_size);
    unsigned char ss_enc[PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES];
    unsigned char ss_dec[PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES];
    
    double *keygen_times = malloc(iterations * sizeof(double));
    double *encaps_times = malloc(iterations * sizeof(double));
    double *decaps_times = malloc(iterations * sizeof(double));
    
    printf("\n--------------------------------------------------\n");
    printf("│  McEliece6960119 (NIST Level 5 - AES-256 eq.)  │\n");
    printf("--------------------------------------------------\n");
    printf("Parameters: n=6960, k=5413, t=119\n");
    printf("Iterations: %d\n", iterations);
    printf("Progress: ");
    fflush(stdout);
    
    // Benchmark Key Generation
    for (int i = 0; i < iterations; i++) {
        if (i % 10 == 0) {
            printf(".");
            fflush(stdout);
        }
        double start = get_time_ms();
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pk, sk);
        double end = get_time_ms();
        keygen_times[i] = end - start;
    }
    
    // Generate a keypair for subsequent tests
    PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pk, sk);
    
    // Benchmark Encapsulation
    for (int i = 0; i < iterations; i++) {
        double start = get_time_ms();
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
        double end = get_time_ms();
        encaps_times[i] = end - start;
    }
    
    // Generate a ciphertext for decapsulation test
    PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
    
    // Benchmark Decapsulation
    for (int i = 0; i < iterations; i++) {
        double start = get_time_ms();
        PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec(ss_dec, ct, sk);
        double end = get_time_ms();
        decaps_times[i] = end - start;
    }
    
    printf(" Done!\n");
    
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
    
    unsigned char *pk = malloc(results.pk_size);
    unsigned char *sk = malloc(results.sk_size);
    unsigned char *ct = malloc(results.ct_size);
    unsigned char ss_enc[PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES];
    unsigned char ss_dec[PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES];
    
    double *keygen_times = malloc(iterations * sizeof(double));
    double *encaps_times = malloc(iterations * sizeof(double));
    double *decaps_times = malloc(iterations * sizeof(double));
    
    printf("\n--------------------------------------------------\n");
    printf("│  HQC-256 (NIST Level 5 - AES-256 equivalent)   │\n");
    printf("--------------------------------------------------\n");
    printf("Parameters: n=46747, k=256, w=133, wr=153\n");
    printf("Iterations: %d\n", iterations);
    printf("Progress: ");
    fflush(stdout);
    
    // Benchmark Key Generation
    for (int i = 0; i < iterations; i++) {
        if (i % 10 == 0) {
            printf(".");
            fflush(stdout);
        }
        double start = get_time_ms();
        PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pk, sk);
        double end = get_time_ms();
        keygen_times[i] = end - start;
    }
    
    // Generate a keypair for subsequent tests
    PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pk, sk);
    
    // Benchmark Encapsulation
    for (int i = 0; i < iterations; i++) {
        double start = get_time_ms();
        PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
        double end = get_time_ms();
        encaps_times[i] = end - start;
    }
    
    // Generate a ciphertext for decapsulation test
    PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
    
    // Benchmark Decapsulation
    for (int i = 0; i < iterations; i++) {
        double start = get_time_ms();
        PQCLEAN_HQC256_CLEAN_crypto_kem_dec(ss_dec, ct, sk);
        double end = get_time_ms();
        decaps_times[i] = end - start;
    }
    
    printf(" Done!\n");
    
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
    printf("\n-------------------------------------------------------------\n");
    printf("  Detailed Results: %s\n", name);
    printf("-------------------------------------------------------------\n");
    
    printf("\nSIZE:\n");
    printf("\t - Public Key: \t\t %7zu bytes (%8.2f KB)\n", 
           results.pk_size, results.pk_size / 1024.0);
    printf("\t - Private Key: \t %7zu bytes (%8.2f KB)\n", 
           results.sk_size, results.sk_size / 1024.0);
    printf("\t - Ciphertext: \t\t %7zu bytes (%8.2f KB)\n", 
           results.ct_size, results.ct_size / 1024.0);
    printf("\t - Total key size: \t %7zu bytes (%8.2f KB)\n", 
           results.pk_size + results.sk_size, 
           (results.pk_size + results.sk_size) / 1024.0);
    
    printf("\nPERFORMANCE (mean ± standard deviation:\n");
    printf("\t - Key Generation: \t %8.3f ± %6.3f ms\n", 
           results.keygen_mean, results.keygen_stddev);
    printf("\t - Encapsulation: \t %8.3f ± %6.3f ms\n", 
           results.encaps_mean, results.encaps_stddev);
    printf("\t - Decapsulation: \t %8.3f ± %6.3f ms\n", 
           results.decaps_mean, results.decaps_stddev);
    
    printf("\nVARIABILITY (Coefficient of Variation):\n");
    printf("\t - Key Generation: \t %5.2f%% %s\n", 
           (results.keygen_stddev / results.keygen_mean) * 100,
           (results.keygen_stddev / results.keygen_mean) < 0.05 ? "(very stable)" : 
           (results.keygen_stddev / results.keygen_mean) < 0.10 ? "(stable)" : "(variable)");
    printf("\t - Encapsulation: \t %5.2f%% %s\n", 
           (results.encaps_stddev / results.encaps_mean) * 100,
           (results.encaps_stddev / results.encaps_mean) < 0.05 ? "(very stable)" : 
           (results.encaps_stddev / results.encaps_mean) < 0.10 ? "(stable)" : "(variable)");
    printf("\t - Decapsulation: \t %5.2f%% %s\n", 
           (results.decaps_stddev / results.decaps_mean) * 100,
           (results.decaps_stddev / results.decaps_mean) < 0.05 ? "(very stable)" : 
           (results.decaps_stddev / results.decaps_mean) < 0.10 ? "(stable)" : "(variable)");
    
    printf("\nTOTAL TIME FOR OPERATIONS:\n");
    printf("\t - KeyGen + Encaps + Decaps: \t %.3f ms\n", 
           results.keygen_mean + results.encaps_mean + results.decaps_mean);
    
    //printf("-------------------------------------------------------------\n");
}

void print_comparison(BenchmarkResults mceliece, BenchmarkResults hqc) {
    printf("\n-------------------------------------------------\n");
    printf("|          COMPARISON (Level 5)                  |\n");
    printf("|      McEliece6960119 vs HQC-256                |\n");
    printf("-------------------------------------------------\n");
    
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
    printf("\t \t * Ratio: \t%.2fx %s\n", 
           (double)mceliece.sk_size / hqc.sk_size,
           mceliece.sk_size > hqc.sk_size ? "(McEliece bigger)" : "(HQC bigger)");
    
    printf("\t - Ciphertext:\n");
    printf("\t \t * McEliece: \t %7zu bytes (%.2f KB)\n", 
           mceliece.ct_size, mceliece.ct_size / 1024.0);
    printf("\t \t * HQC: \t %7zu bytes (%.2f KB)\n", 
           hqc.ct_size, hqc.ct_size / 1024.0);
    printf("\t \t * Ratio: \t%.2fx %s\n", 
           (double)mceliece.ct_size / hqc.ct_size,
           mceliece.ct_size > hqc.ct_size ? "(McEliece bigger" : "(HQC bigger)");
    
    printf("\nSPEED COMPARISON:\n");
    printf("\t - Key Generation:\n");
    printf("\t \t * McEliece: \t %.3f ± %.3f ms\n", 
           mceliece.keygen_mean, mceliece.keygen_stddev);
    printf("\t \t * HQC: \t %.3f ± %.3f ms\n", 
           hqc.keygen_mean, hqc.keygen_stddev);
    printf("\t \t * Ratio: \t %.2fx %s\n", 
           mceliece.keygen_mean / hqc.keygen_mean,
           mceliece.keygen_mean > hqc.keygen_mean ? "(HQC faster)" : "(McEliece faster)");
    
    printf("\t - Encapsulation:\n");
    printf("\t \t * McEliece: \t %.3f ± %.3f ms\n", 
           mceliece.encaps_mean, mceliece.encaps_stddev);
    printf("\t \t * HQC: \t %.3f ± %.3f ms\n", 
           hqc.encaps_mean, hqc.encaps_stddev);
    printf("\t \t * Ratio: \t %.2fx %s\n", 
           mceliece.encaps_mean / hqc.encaps_mean,
           mceliece.encaps_mean > hqc.encaps_mean ? "(HQC faster)" : "(McEliece faster)");
    
    printf("\t - Decapsulation:\n");
    printf("\t \t * McEliece: \t %.3f ± %.3f ms\n", 
           mceliece.decaps_mean, mceliece.decaps_stddev);
    printf("\t \t * HQC: \t %.3f ± %.3f ms\n", 
           hqc.decaps_mean, hqc.decaps_stddev);
    printf("\t \t * Ratio: \t %.2fx %s\n", 
           mceliece.decaps_mean / hqc.decaps_mean,
           mceliece.decaps_mean > hqc.decaps_mean ? "(HQC faster)" : "(McEliece faster)");
    
    double mceliece_total = mceliece.keygen_mean + mceliece.encaps_mean + mceliece.decaps_mean;
    double hqc_total = hqc.keygen_mean + hqc.encaps_mean + hqc.decaps_mean;
    
    printf("\nTOTAL TIME:\n");
    printf("\t - McEliece: \t %.3f ms\n", mceliece_total);
    printf("\t - HQC: \t %.3f ms\n", hqc_total);
    printf("\t - Difference: \t %.3f ms (%.1f%%)\n", 
           fabs(mceliece_total - hqc_total),
           fabs(mceliece_total - hqc_total) / ((mceliece_total + hqc_total) / 2) * 100);
    
    double mceliece_cv = ((mceliece.keygen_stddev / mceliece.keygen_mean) + 
                          (mceliece.encaps_stddev / mceliece.encaps_mean) + 
                          (mceliece.decaps_stddev / mceliece.decaps_mean)) / 3 * 100;
    double hqc_cv = ((hqc.keygen_stddev / hqc.keygen_mean) + 
                     (hqc.encaps_stddev / hqc.encaps_mean) + 
                     (hqc.decaps_stddev / hqc.decaps_mean)) / 3 * 100;
    
    printf("\nSTABILITY (less variabile = more predictable):\n");
    printf("\t - McEliece average CV: \t %.2f%%\n", mceliece_cv);
    printf("\t - HQC average CV: \t\t %.2f%%\n", hqc_cv);
    printf("\t - More stable: \t\t %s\n", mceliece_cv < hqc_cv ? "McEliece" : "HQC");
    
    double mceliece_size_total = mceliece.pk_size + mceliece.sk_size;
    double hqc_size_total = hqc.pk_size + hqc.sk_size;
    
    printf("\nRECAP:\n");
    printf("\t - Size: \t\t %s (%.1f%% smaller)\n", 
           mceliece_size_total < hqc_size_total ? "McEliece" : "HQC",
           fabs(mceliece_size_total - hqc_size_total) / ((mceliece_size_total + hqc_size_total) / 2) * 100);
    printf("\t - Speed: \t\t %s (%.1f%% faster)\n", 
           mceliece_total < hqc_total ? "McEliece" : "HQC",
           fabs(mceliece_total - hqc_total) / ((mceliece_total + hqc_total) / 2) * 100);
    printf("\t - Stability: \t\t %s\n", 
           mceliece_cv < hqc_cv ? "McEliece" : "HQC");
    printf("\t - Security Level: \t EVEN (Level 5)\n");
    
    
    printf("-------------------------------------------------------------\n");
}

int main() {
       printf("\n");
       printf("--------------------------------------------------\n");
       printf("|                                                |\n");
       printf("|    BENCHMARK POST-QUANTUM CRYPTOGRAPHY         |\n");
       printf("|    McEliece6960119 vs HQC-256                  |\n");
       printf("|                                                |\n");
       printf("|    Library: PQClean                            |\n");
       printf("|    Statistics: Average + Standard Deviation    |\n");
       printf("|                                                |\n");
       printf("--------------------------------------------------\n");

    
       BenchmarkResults mceliece_results = benchmark_mceliece(NUM_ITERATIONS);
       BenchmarkResults hqc_results = benchmark_hqc(NUM_ITERATIONS);
       
       print_results("McEliece6960119", mceliece_results);
       print_results("HQC-256", hqc_results);
       print_comparison(mceliece_results, hqc_results);
       
       //./benchmark_mceliece_hqc > risultati_$(date +%%Y%%m%%d_%%H%%M%%S).txt
       
       return 0;
}
