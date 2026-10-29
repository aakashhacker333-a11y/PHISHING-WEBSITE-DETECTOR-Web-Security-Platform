import random

def sensor_node(node):
    temp = random.randint(25, 35)
    humidity = random.randint(50, 80)

    print(node, "Temperature:", temp, "°C")
    print(node, "Humidity:", humidity, "%")

    return temp, humidity


def base_station():
    total_temp = 0
    total_humidity = 0

    for i in range(1, 4):
        temp, humidity = sensor_node("Mote " + str(i))
        total_temp += temp
        total_humidity += humidity

    print("\nBase Station - Aggregated Data")
    print("Average Temperature:", round(total_temp / 3, 2), "°C")
    print("Average Humidity:", round(total_humidity / 3, 2), "%")


base_station()
