with open("Traces_A.dat", "rb") as file:
    nr_of_points = file.read(4)

print(nr_of_points)
print(nr_of_points.hex(" "))

little_endian = (
    nr_of_points[0]
    + nr_of_points[1] * 256
    + nr_of_points[2] * 256**2
    + nr_of_points[3] * 256**3
)

print("little endian:", little_endian)

big_endian = (
    nr_of_points[0] * 256**3
    + nr_of_points[1] * 256**2
    + nr_of_points[2] * 256
    + nr_of_points[3]
)

print("big endian:", big_endian)