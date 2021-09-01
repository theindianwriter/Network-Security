import rc4 as algorithm
import helper
import math
import matplotlib.pyplot as plt

#for calculating the randomness R vaue
def get_randomness(key1,key2,num_of_counters,len_of_keystream):

    K1 = algorithm.RC4(key1)
    K2 = algorithm.RC4(key2)

    keystream1 = ''
    keystream2 = ''

    for i in range(len_of_keystream):
        keystream1 += "".join('{0:08b}'.format(next(K1)))
        keystream2 += "".join('{0:08b}'.format(next(K2)))
    #simple frequency counting technique for calculating the randomness
    counters = [0 for i in range(num_of_counters)]
    seq_len = int(math.log2(num_of_counters))
    N = int(len_of_keystream*8 - seq_len)

    
    for i in range(0,N):
        counters[int(keystream1[i:i+seq_len],2)^int(keystream2[i:i+seq_len],2)] += 1

     
    SD = helper.calculate_SD(counters)
    randomness = SD*num_of_counters/N
    return randomness

def experiment(iterations,num_of_toggling_bits,num_of_counters,len_of_keystream):
    

    #first taking different random keys and then toggling key bits at different random 
    #positons and averaging out the results for a better stable result
    average_randomness = 0
    for i in range(iterations):
        key1 = helper.rand_key(2048)
        for i in range(iterations):
            key2 = helper.rand_toggle_bits(key1,num_of_toggling_bits)
            average_randomness += get_randomness(key1,key2,num_of_counters,len_of_keystream)
    return average_randomness/(iterations*iterations)


def main():
    #different samples for different length of key stream and different number of toggling bits
    stream_size = [2,4,8,32,128,1024]
    toggling_bits = [1,2,4,8,16,32]
    #all the results are shown here
    results = {}

    for s in stream_size:
        R = []
        for t in toggling_bits:
            #do the following experiment with the given data
            R.append(experiment(20,t,256,s))
        results[s] = R
        #for plotting
        helper.Plot(toggling_bits,results[s],"number of toggling bits","Randomness")

    #printing the result and plotting the results in a single graph
    print(results)
    helper.PlotAll(results,toggling_bits)



if __name__ == "__main__":
    main()