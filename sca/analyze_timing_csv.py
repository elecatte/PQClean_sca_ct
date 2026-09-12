#!/usr/bin/env python3

import sys
import os
import pandas as pd
import numpy as np
from scipy import stats
import matplotlib.pyplot as plt


def welch_t_test(a, b):
    """T-test di Welch (varianze non necessariamente uguali)."""
    t_stat, p_value = stats.ttest_ind(a, b, equal_var=False)
    return t_stat, p_value


def cohens_d(a, b):
    """Effect size (utile per capire se il leak, oltre che significativo,
    e' anche rilevante in termini pratici)."""
    n_a, n_b = len(a), len(b)
    pooled_std = np.sqrt(((n_a - 1) * np.var(a, ddof=1) +
                           (n_b - 1) * np.var(b, ddof=1)) / (n_a + n_b - 2))
    return (np.mean(a) - np.mean(b)) / pooled_std


def analyze_file(path, t_threshold=4.5):
    df = pd.read_csv(path)

    if "class" not in df.columns or "cycles" not in df.columns:
        print(f"[SKIP] {path}: colonne attese 'class,cycles' non trovate")
        return None

    classes = df["class"].unique()
    if len(classes) != 2:
        print(f"[SKIP] {path}: attese esattamente 2 classi, trovate {len(classes)}")
        return None

    class_a, class_b = classes[0], classes[1]
    a = df[df["class"] == class_a]["cycles"].to_numpy()
    b = df[df["class"] == class_b]["cycles"].to_numpy()

    # Rimozione outlier via percentili (1%-99%): utile perche' interruzioni
    # del kernel/scheduler generano code lunghe che non c'entrano col leak
    # crittografico e possono mascherare o falsare il test statistico.
    def trim(x):
        lo, hi = np.percentile(x, [1, 99])
        return x[(x >= lo) & (x <= hi)]

    a_trim, b_trim = trim(a), trim(b)

    t_raw, p_raw = welch_t_test(a, b)
    t_trim, p_trim = welch_t_test(a_trim, b_trim)
    d = cohens_d(a_trim, b_trim)

    print(f"\n{'=' * 60}")
    print(f"File: {path}")
    print(f"{'=' * 60}")
    print(f"Classe '{class_a}': n={len(a)}  media={np.mean(a):.1f}  "
          f"mediana={np.median(a):.1f}  std={np.std(a, ddof=1):.1f}")
    print(f"Classe '{class_b}': n={len(b)}  media={np.mean(b):.1f}  "
          f"mediana={np.median(b):.1f}  std={np.std(b, ddof=1):.1f}")
    print(f"\nDati grezzi:      t={t_raw:.3f}  p={p_raw:.2e}")
    print(f"Dati trimmati 1-99%: t={t_trim:.3f}  p={p_trim:.2e}")
    print(f"Cohen's d (su dati trimmati): {d:.3f}")

    if abs(t_trim) > t_threshold:
        print(f"=> LEAK RILEVATO (|t|={abs(t_trim):.2f} > soglia {t_threshold})")
    else:
        print(f"=> Nessun leak rilevato con questa potenza statistica "
              f"(|t|={abs(t_trim):.2f} <= soglia {t_threshold})")

    return {
        "path": path,
        "class_a": class_a, "class_b": class_b,
        "a": a_trim, "b": b_trim,
        "t": t_trim, "p": p_trim, "d": d,
    }


def plot_result(result, outdir="."):
    a, b = result["a"], result["b"]
    class_a, class_b = result["class_a"], result["class_b"]
    base = os.path.splitext(os.path.basename(result["path"]))[0]

    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))

    # Istogrammi sovrapposti
    bins = 80
    axes[0].hist(a, bins=bins, alpha=0.6, label=class_a, density=True)
    axes[0].hist(b, bins=bins, alpha=0.6, label=class_b, density=True)
    axes[0].set_xlabel("CPU cycles")
    axes[0].set_ylabel("Density")
    axes[0].set_title(f"Timing distribution - {base}")
    axes[0].legend()

    # Box plot per confronto rapido di mediana/dispersione
    try:
        axes[1].boxplot([a, b], tick_labels=[class_a, class_b], showfliers=False)
    except TypeError:
        # Compatibilita' con matplotlib < 3.9, dove il parametro si
        # chiamava ancora "labels" invece di "tick_labels".
        axes[1].boxplot([a, b], labels=[class_a, class_b], showfliers=False)
    axes[1].set_ylabel("CPU cycles")
    axes[1].set_title(f"Box plot - {base}")

    plt.tight_layout()
    outpath = os.path.join(outdir, f"{base}_analysis.png")
    plt.savefig(outpath, dpi=150)
    plt.close(fig)
    print(f"Grafico salvato in: {outpath}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    results = []
    for path in sys.argv[1:]:
        if not os.path.isfile(path):
            print(f"[SKIP] {path}: file non trovato")
            continue
        res = analyze_file(path)
        if res is not None:
            results.append(res)
            plot_result(res)

    if not results:
        print("\nNessun file valido analizzato.")
        return

    print(f"\n{'=' * 60}")
    print("RIEPILOGO")
    print(f"{'=' * 60}")
    for r in results:
        verdict = "LEAK" if abs(r["t"]) > 4.5 else "no leak"
        print(f"  {os.path.basename(r['path']):40s} t={r['t']:7.3f}  "
              f"d={r['d']:6.3f}  -> {verdict}")


if __name__ == "__main__":
    main()