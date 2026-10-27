import matplotlib.pyplot as plt

def load_traces(filename):
    traces = []

    with open(filename, "rb") as file:
        while True:
            nr_p = file.read(4)

            # wenn keine bytes mehr gelesen werden können, Schleife beenden
            if not nr_p:
                break

            nr_of_points = 0 # uint32
            for i, value in enumerate(nr_p):
                # 232 * 256^0 + 3 * 256^1 = 1000; byte ist zahl zur basis 256
                nr_of_points += value * (256 ** i)
            
            # jeder Messpunkt laut Aufgabenstellung genau ein Byte -> bytes entsprechen Messpunkten
            data = file.read(nr_of_points)

            values = list(data)

            trace = [] # int8 vorzeichenbehaftet -128 bis 127
            for value in data:
                if value < 128:
                    trace.append(value)
                else:
                    value -= 256        # Wert von 128-255 um 256 reduzieren -> Wertebereich von -128 bis -1
                    trace.append(value)
            
            # Den vollständigen Trace speichern.
            traces.append(trace)

    return traces

traces_a = load_traces("Traces_A.dat")
traces_b = load_traces("Traces_B.dat")

# plot
def plot_all_traces(traces, filename, output_png):
    plt.figure(figsize=(24,6))

    i = 1
    farben = ["blue", "red", "purple", "orange", "green"]
    for trace in traces:
        plt.plot(
            range(len(trace)), # x-Werte von 0 bis len(trace)-1
            trace,
            label=f"Trace {i}",
            color=farben[i - 1],
            linewidth=0.8    
        )
        i+=1

    plt.title(f"Power Traces - {filename}")
    plt.xlabel("Messpunkt")
    plt.ylabel("Leistungsmesswert")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()

    plt.savefig(output_png, dpi=300)
    plt.close()

    print("Plot gespeichert: ", output_png)


plot_all_traces(traces_a, "Traces_A.dat", "Traces_A.png")
plot_all_traces(traces_b, "Traces_B.dat", "Traces_B.png")
