import csv
import numpy as np

# CSV Datei lesen + Daten laden
def load_data(file):
    plaintexts = []
    times = []
    ciphertexts = []

    with open(file, "r") as f:
        reader = csv.reader(f)
        
        for row in reader:
            # 16 bytes plaintext + 1 time + 16 bytes ciphertext
            plaintexts.append([int(x) for x in row[:16]])
            times.append(row[16])
            ciphertexts.append([int(x) for x in row[17:33]])

    return (
        np.ascontiguousarray(plaintexts, dtype=np.uint8),
        np.ascontiguousarray(times, dtype=np.float64),
        np.ascontiguousarray(ciphertexts, dtype=np.uint8)
    )
