import ctypes
import numpy as np
import matplotlib.pyplot as plt
import time

from load_csv import load_data
# load data
print("Loading CSV...")
plaintexts, times, ciphertexts = load_data("./TimingCache_noiseFree_B=4.csv")
print(f"CSV loaded successfully!  ({len(times)} traces)")

# round 1

def t_value_computation_pair(plaintexts, times, byte_i, byte_j):
    t_values = np.zeros(64) # array für die 64 mögl. key-diffs

    # upper 6 bits von XOr-Differenz der beiden pt-bytes; cache: B = 4 -> lower 2 bits ignorieren
    differences = (plaintexts[:, byte_i] ^plaintexts[:, byte_j]) >> 2

    # Differenzen ausprobieren (64, alle):
    for guess in range(64):
        collision = differences == guess # Gruppen: True = col, False != col

        # laufzeiten
        times_collision = times[collision]    
        times_no_collision = times[~collision]

        if len(times_collision) < 2 or len(times_no_collision) < 2: # mind. 2 MW / Gruppe
            continue

        mean_collision = np.mean(times_collision) # Durschschnittl. Laufzeit
        mean_no_collision = np.mean(times_no_collision)

        # varianz (ddof=1 = Stichprobenvarianz)
        var_collision = np.var(times_collision, ddof=1)
        var_no_collision= np.var(times_no_collision, ddof=1)

        denominator = np.sqrt(var_collision / len(times_collision) + var_no_collision / len(times_no_collision))

        # t_value
        if denominator > 1e-12:
            t_values[guess] = (mean_no_collision - mean_collision) / denominator

    return t_values

def round1_attack(plaintexts, times):
    deltas = np.zeros(15, dtype=int) # key-differenzen
    all_t_values = []

    start = time.perf_counter()

    # vergleiche Byte 0 mit allen anderen Bytes
    for j in range(1,16):
        t_values = t_value_computation_pair(plaintexts, times, 0, j) # t_test für aktuelle bytes (0, j)

        best = np.argmax(np.abs(t_values))

        deltas[j - 1] = best # best key-diff (weil j bei 1 beginnt)

        all_t_values.append(t_values)
        print(f"Pair (0,{j}): "
              f"best delta = {best}, "
              f"|t| = {abs(t_values[best])}")

    print(f"Laufzeit Runde 1: {time.perf_counter() - start:.1f}s")
    return deltas, np.array(all_t_values)

# plot

def plot_k_t(all_t_values, deltas):
    for i, j in enumerate(range(1, 16)):

        plt.figure(figsize=(10, 5))
        plt.plot(range(64), all_t_values[i], color="green")
        plt.scatter(deltas[i], all_t_values[i, deltas[i]], color="red", zorder=3, label="bestes delta")
        plt.xlabel("delta (key guess)")
        plt.ylabel("t-value")
        plt.title(f"Pair (0,{j}): t-test")
        plt.axvline(deltas[i], color="red", linestyle="--", alpha=0.5) #linie
        plt.legend()
        plt.grid()
        plt.tight_layout()
        plt.savefig(f"plots/plot_k_t_n/plot_k_t_{j}.png")
        plt.close()


def plot_ntraces(plaintexts, times, deltas, step=10_000):
    max_n = len(times)
    ns = list(range(step, max_n + 1, step))

    for idx, j in enumerate(range(1, 16)):
        print(f"  Pair (0,{j}) ...", end=" ", flush=True)
        best_delta = deltas[idx]
        t_over_n = np.zeros((len(ns), 64))

        for i, n in enumerate(ns):
            t_over_n[i] = t_value_computation_pair(plaintexts[:n], times[:n], 0, j)

        plt.figure(figsize=(11, 5))
        for delta in range(64):
            if delta == best_delta:
                plt.plot(ns, t_over_n[:, delta], "r-", linewidth=2.2, label=f"richtiges delta={best_delta}")
            else:
                plt.plot(ns, t_over_n[:, delta], "b-", alpha=0.12, linewidth=0.6)
        plt.xlabel("# traces")
        plt.ylabel("t-value")
        plt.title(f"Pair (0,{j}) - t-value vs. # traces")
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(f"plots/plot_ntraces_t_n/plot_ntraces_t_{j:02d}.png", dpi=120)
        plt.close()
        print("fertig")

deltas, all_t_values = round1_attack(plaintexts, times)
plot_k_t(all_t_values, deltas)
plot_ntraces(plaintexts, times, deltas)
print("deltas:", deltas)