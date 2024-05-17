import scapy.all as scp
import numpy as np

count = 100

while True:
    package_load_arr = []
    unique_package_load = []
    package_no_load = 0

    package = scp.sniff(count=count)

    for j in range(count):
        try:
            package_load_arr.append(package[j])
        except:
            print("Package without load:", package[j].summary())
            package_no_load += 1

    def unique(list1):
        unique_list = []

        for x in list1:
            if x not in unique_list:
                unique_list.append(x)
        for x in unique_list:
            unique_package_load.append(x)

    unique(package_load_arr)

    print(len(unique_package_load) + package_no_load)
