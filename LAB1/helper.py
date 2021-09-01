
import random
import math
import matplotlib.pyplot as plt

'''
this python file contains some random functions like to generate random keys of a given length,
function to toggle few bits at random positions,calculating standard deviation of the data,
plotting different graphs etc.

'''

def rand_key(key_length):
    key = []
    for i in range(key_length):
        key.append(random.randint(0,1))
    return key


def rand_toggle_bits(key_in_bits,num_of_bits):
    key_length = len(key_in_bits)
    toggled_key_in_bits = list(key_in_bits)
    rand_bits_position = []

    while num_of_bits:
        pos = random.randint(0,key_length-1)
        if pos not in rand_bits_position:
            toggled_key_in_bits[pos] = 0 if key_in_bits[pos] == 1 else 1
            rand_bits_position.append(pos)
            num_of_bits -= 1

    return toggled_key_in_bits


def calculate_SD(data):
    n = len(data)
    mean = sum(data)/n
    deviations = [(x-mean)**2 for x in data]
    variance = sum(deviations)/n
    SD = math.sqrt(variance)
    return SD

def Plot(X_axis,Y_axis,X_label,Y_label):
    plt.plot(X_axis,Y_axis,color = 'r')
    plt.xlabel(X_label) 
    plt.ylabel(Y_label)
    plt.title("Number of Toggling Bits vs Randomness")
    plt.show()

def PlotAll(results,toggling_bits):
    plt.plot(toggling_bits,results[2],label = "2 byte keystream")
    plt.plot(toggling_bits,results[4],label = "4 byte keystream")
    plt.plot(toggling_bits,results[8],label = "8 byte keystream")
    plt.plot(toggling_bits,results[32],label = "32 byte keystream")
    plt.plot(toggling_bits,results[128],label = "128 byte keystream")
    plt.plot(toggling_bits,results[1024],label = "1024 byte keystream")
    plt.xlabel("number of toggling bits") 
    plt.ylabel("Randomness")
    plt.title("Number of Toggling Bits vs Randomness")
    plt.legend()
    plt.show()