from MyCovertChannel import MyCovertChannel
import time 

channel = MyCovertChannel()

start = time.time()
channel.send(burst_size_0=1, burst_size_1=2, idle_time=0.5)
end = time.time()

print(f"Bits per second: {128 / (end - start)}")
