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

// Include McEliece e HQC (stessi target del benchmark di performance)
#include "crypto_kem/mceliece6960119/clean/api.h"
#include "crypto_kem/hqc-256/clean/api.h"

// -------------------------------------------------------------------------
// CONFIGURAZIONE
// -------------------------------------------------------------------------
// N. di misurazioni totali per algoritmo. McEliece a livello 5 e' lento in
// decapsulazione: se il test impiega troppo, abbassa questo valore.
#define NUM_MEASUREMENTS 20
#define WARMUP_ITERATIONS 2
// Soglia standard usata da dudect per dichiarare un leak statisticamente
// significativo (corrisponde a una confidenza molto alta, > 99.999%).
#define T_THRESHOLD 4.5

// -------------------------------------------------------------------------
// TIPI GENERICI PQClean (stessa firma per tutti i KEM della libreria)
// -------------------------------------------------------------------------
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
// HELPER (identici allo stile del benchmark di performance)
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

// t-test di Welch tra le due popolazioni di cicli
double welch_t_test(double *a, int na, double *b, int nb) {
    double mean_a = calculate_mean(a, na);
    double mean_b = calculate_mean(b, nb);
    double var_a = calculate_var(a, na, mean_a);
    double var_b = calculate_var(b, nb, mean_b);
    double se = sqrt(var_a / na + var_b / nb);
    return (mean_a - mean_b) / se;
}

// Flippa n_bits bit distinti scelti a caso in buf (lunghezza len byte).
// Usato per costruire ciphertext "invalidi" a partire da uno valido, con un
// livello di corruzione controllato (utile per esplorare il confine della
// capacita' di correzione del decoder).
void corrupt_ciphertext(unsigned char *buf, size_t len, int n_bits) {
    size_t total_bits = len * 8;
    if ((size_t)n_bits > total_bits) n_bits = (int)total_bits;

    // Evitiamo di flippare due volte lo stesso bit tenendo traccia di
    // quelli gia' usati (approccio semplice, va benissimo per n_bits
    // piccolo o anche fino a total_bits/2 su ciphertext di questa taglia).
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
// MOTORE GENERICO DEL TEST: fixed-vs-random su crypto_kem_dec
// -------------------------------------------------------------------------
void run_timing_test(KemAlgo *algo, int n_measurements) {
    printf("\n--------------------------------------------------\n");
    printf("  Timing leakage test (Level 1): %s\n", algo->name);
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

    // Una sola coppia di chiavi per l'intero test: vogliamo isolare il
    // solo effetto del ciphertext (classe fixed vs classe random) a
    // parita' di chiave segreta.
    algo->keypair(pk, sk);

    // Ciphertext "fixed": generato una volta sola e riutilizzato per
    // tutte le misurazioni di classe 0.
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
            // Classe 0: ciphertext fisso
            uint64_t start = get_cpu_cycles();
            algo->decaps(ss_tmp, ct_fixed, sk);
            uint64_t end = get_cpu_cycles();
            cycles_fixed[n_fixed++] = (double)(end - start);
        } else {
            // Classe 1: ciphertext fresco (generato PRIMA di iniziare a
            // misurare, cosi' il costo di encaps non entra nel timing)
            algo->encaps(ct_random, ss_tmp, pk);
            uint64_t start = get_cpu_cycles();
            algo->decaps(ss_tmp, ct_random, sk);
            uint64_t end = get_cpu_cycles();
            cycles_random[n_random++] = (double)(end - start);
        }

        if (i % 2000 == 0) { printf("."); fflush(stdout); }
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
        printf("\t=> LEAK RILEVATO (|t| > %.1f): il tempo di decapsulazione\n", T_THRESHOLD);
        printf("\t   dipende in modo statisticamente significativo dal ciphertext.\n");
    } else {
        printf("\t=> Nessun leak rilevato in questo esperimento (|t| <= %.1f).\n", T_THRESHOLD);
        printf("\t   Non prova constant-timeness: aumenta NUM_MEASUREMENTS per\n");
        printf("\t   maggiore potenza statistica.\n");
    }

    // Esporta i campioni grezzi per analisi/grafici successivi (es. Python)
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
// MOTORE GENERICO DEL TEST: valido vs corrotto su crypto_kem_dec
// -------------------------------------------------------------------------
// A differenza di run_timing_test (che confronta ciphertext SEMPRE validi
// ma diversi tra loro), questo test isola specificamente il confine tra
// "il decoder accetta" e "il decoder rifiuta" (implicitamente, via FO
// transform). E' il meccanismo teorico discusso: se il tempo di
// decapsulazione dipende da questo confine, il rifiuto implicito non
// protegge davvero dall'oracolo timing.
//
// n_bits_flip: quanti bit del ciphertext valido vengono corrotti prima
// della decapsulazione, nella classe "corrupted". Usare un valore piccolo
// (es. 1) per restare vicino al confine di decodifica, e uno grande
// (es. meta' dei bit del ciphertext) per un rifiuto "netto".
void run_corrupted_test(KemAlgo *algo, int n_measurements, int n_bits_flip, const char *label) {
    printf("\n--------------------------------------------------\n");
    printf("  Timing leakage test (Level 1, valido vs corrotto): %s [%s]\n", algo->name, label);
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
        // Ciphertext valido fresco a ogni iterazione: sia la classe
        // "valid" sia la base della classe "corrupted" partono da qui,
        // cosi' l'unica differenza sistematica tra le due classi e'
        // la corruzione applicata, non il contenuto generico del ciphertext.
        algo->encaps(ct_valid, ss_tmp, pk);

        int cls = rand() % 2;
        if (cls == 0) {
            uint64_t start = get_cpu_cycles();
            algo->decaps(ss_tmp, ct_valid, sk);
            uint64_t end = get_cpu_cycles();
            cycles_valid[n_valid++] = (double)(end - start);
        } else {
            memcpy(ct_corrupt, ct_valid, algo->ct_size);
            corrupt_ciphertext(ct_corrupt, algo->ct_size, n_bits_flip);

            uint64_t start = get_cpu_cycles();
            algo->decaps(ss_tmp, ct_corrupt, sk);
            uint64_t end = get_cpu_cycles();
            cycles_corrupt[n_corrupt++] = (double)(end - start);
        }

        if (i % 2000 == 0) { printf("."); fflush(stdout); }
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
        printf("\t=> LEAK RILEVATO (|t| > %.1f): il tempo di decapsulazione\n", T_THRESHOLD);
        printf("\t   dipende dal fatto che il ciphertext sia valido o rifiutato.\n");
        printf("\t   Questo e' rilevante perche' bypassa la protezione del\n");
        printf("\t   rifiuto implicito della trasformata FO.\n");
    } else {
        printf("\t=> Nessun leak rilevato in questo esperimento (|t| <= %.1f).\n", T_THRESHOLD);
    }

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
    printf("  SCA Level 1 - Timing leakage test (fixed vs random)\n");
    printf("  Libreria: PQClean\n");
    printf("==================================================\n");

    set_cpu_affinity(0);
    set_high_priority();
    warmup_cpu();
    srand((unsigned int)time(NULL));

    KemAlgo mceliece = {
        .name = "mceliece6960119",
        .keypair = (keypair_fn)PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair,
        .encaps = (enc_fn)PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc,
        .decaps = (dec_fn)PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec,
        .pk_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES,
        .sk_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES,
        .ct_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES,
        .ss_size = PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES,
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

    // Test 1: fixed vs random (leakage generico legato al contenuto)
    run_timing_test(&mceliece, NUM_MEASUREMENTS);
    run_timing_test(&hqc, NUM_MEASUREMENTS);

    // Test 2: valido vs corrotto (isola il confine di rifiuto implicito)
    // Corruzione minima: 1 bit flippato, resta vicino al confine di
    // decodifica ed e' il caso piu' interessante per un attacco realistico.
    run_corrupted_test(&mceliece, NUM_MEASUREMENTS, 1, "1bit");
    run_corrupted_test(&hqc, NUM_MEASUREMENTS, 1, "1bit");

    // Corruzione pesante: meta' dei bit del ciphertext, forza un rifiuto
    // "netto" e serve da termine di paragone per capire quanto e' grande
    // la differenza di comportamento del decoder tra i due estremi.
    run_corrupted_test(&mceliece, NUM_MEASUREMENTS, (int)(mceliece.ct_size * 4), "heavy");
    run_corrupted_test(&hqc, NUM_MEASUREMENTS, (int)(hqc.ct_size * 4), "heavy");

    printf("\n==================================================\n");
    printf("Test completato. Analizza i CSV generati per istogrammi/densita'.\n");
    printf("==================================================\n");

    return 0;
}