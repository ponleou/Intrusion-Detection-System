import scapy.all as scp
import datetime as dt

count = 100

while True:
    package_load_arr = []
    unique_package_load = []
    package_no_load = 0

    time_before_sniff = dt.datetime.now()
    package = scp.sniff(count=count)
    time_after_sniff = dt.datetime.now()
    print(time_after_sniff - time_before_sniff)

    for j in range(count):
        package_load_arr.append(package[j])

    def unique(list1):
        unique_list = []

        for x in list1:
            if x not in unique_list:
                unique_list.append(x)
        for x in unique_list:
            unique_package_load.append(x)

    unique(package_load_arr)

    print(len(unique_package_load) + package_no_load)
