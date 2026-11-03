import csv
import numpy as np

np.random.seed(42)

number_of_samples = 100

with open("testdata.csv", "w", newline="") as f:
    writer = csv.writer(f)

    for i in range(number_of_samples):
        plaintext = np.random.randint(0, 256, size=16)
        time_value = np.random.normal(100, 5)
        writer.writerow(list(plaintext) + [time_value])
