import ctypes
import numpy as np
import matplotlib.pyplot as plt
import time

from round1 import load_data, round1_attack

lib = ctypes.CDLL("./attack.so") # C-Library laden

# datentypen für C-Funktionen
u8 = np.ctypeslib.ndpointer(dtype=np.uint8, flags="C_CONTIGUOUS")
f64 = np.ctypeslib.ndpointer(dtype=np.float64, flags="C_CONTIGUOUS")
i32 = np.ctypeslib.ndpointer(dtype=np.int32, flags="C_CONTIGUOUS")

# round 2

# in: pt, times, # messungen und deltas; out: t_werte als Array
lib.attack_round2.argtypes = [u8, f64, ctypes.c_int, i32, f64]
lib.attack_round2.restype = None

lib.brute_force.argtypes = [u8, u8, u8, ctypes.c_int, u8] # brute Force für den Rest
lib.brute_force.restype=ctypes.c_int

lib.verify_key.argtypes = [u8, u8, u8, ctypes.c_int] 
lib.verify_key.restype = ctypes.c_int

def round2_attack(plaintexts, times, deltas):

    #16.384 mögliche Kandidaten: 64 Möglichkeiten für g und je 4 für die lower 2 Bits der vier keybytes
    t_values = np.zeros(64 * 4 * 4 * 4 * 4, dtype=np.float64)

    start = time.perf_counter()
    lib.attack_round2(plaintexts, times, len(times), deltas.astype(np.int32), t_values)
    print(f"Laufzeit Runde 2: {time.perf_counter() - start:.1f}s")

    # flaches array mit 12384 Werten zu 5D-numpy-Array
    #(g, low2 von k0, low2 von k5, low2 von k10, low2 von k15)
    t_values = t_values.reshape(64, 4, 4, 4, 4)

    best = np.unravel_index(np.argmax(t_values), t_values.shape) # Pos Kandidat mit höchstem t-value 

    best_score = t_values[best]

    print(
        f"Bester Kandidat: g={best[0]}, "
        f"low2(k0,k5,k10,k15)={best[1:]}, "
        f"score={best_score:.3f}"
    )

    return t_values, best


# plot

def plot_extension(t_values, best):
    values = t_values.flatten() # alle 16384 values zu liste

    best_index = np.ravel_multi_index(best, t_values.shape)

    plt.figure(figsize=(12, 5))
    plt.plot(values, linewidth=0.6, color="green")
    plt.scatter(
        best_index,
        values[best_index],
        color="red",
        label="Bester Kandidat",
        zorder=3
    )
    plt.xlabel("Kandidat")
    plt.ylabel("Kombinierter t-Wert")
    plt.title("Round-2-Angriff: 16.384 Kandidaten")
    plt.legend()
    plt.grid()
    plt.savefig("plots/plot_extension.png", dpi=200)
    plt.close()


# reconstruct upper 6 bit of keybytes
def build_top6_full(deltas, g, l0, l5, l10, l15):
    top6 = np.zeros(16, dtype=np.uint8)

    top6[0] = g #erstes byte als Referenz

    # restliche obere 6 Bit aus round 1
    for j in range(1, 16):
        top6[j] = g ^ deltas[j - 1]

    key_bytes = (top6 << 2).astype(np.uint8) # (lower 2 bits sind zunächst noch 0)

    # gefundene unteren 2 Bit eintragen
    key_bytes[0] = (g << 2) + l0
    key_bytes[5] = (top6[5] << 2) + l5
    key_bytes[10] = (top6[10] << 2) + l10
    key_bytes[15] = (top6[15] << 2) + l15

    return key_bytes


# key-recovery

def recover_key(plaintexts, ciphertexts, top6_full, n_check=6):
    found_key = np.zeros(16, dtype=np.uint8)

    test_pt = np.ascontiguousarray(plaintexts[:n_check])
    test_ct = np.ascontiguousarray(ciphertexts[:n_check])

    start = time.perf_counter()

    success = lib.brute_force(top6_full, test_pt, test_ct, n_check, found_key)
    print(f"Brute Force: {time.perf_counter() - start:.1f}s, gefunden={bool(success)}")

    return found_key

# Programm

pt, times, ct = load_data("TimingCache_noiseFree_B=4.csv")

deltas, _ = round1_attack(pt, times) # round 1, key diffs
t_values, best = round2_attack(pt, times, deltas) # round 2 und fehlende keybits
plot_extension(t_values, best)
top6_full = build_top6_full(deltas, *best) # upper 6 + lower 2 bits

key = recover_key(pt, ct, top6_full)
print("Key (dezimal):", list(key))
print("Key (hex):    ", key.tobytes().hex())

with open("key.txt", "w") as file:
    file.write("Decimal: " + " ".join(map(str, key.tolist())) + "\n")
    file.write("Hex: " + key.tobytes().hex() + "\n")
