import threading
from time import sleep

def threading_function(a:int, b:int):
    sleep(a)
    sum = a+ b
    print("we did it... {}".format(sum))
    # what now?


# Regarding the difference between `start()` and `run()`:  `start()` creates a 
# thread and _then_ the new thread calls `run()` to execute the function specified.
# If your main thread just calls `run()` (instead of `start()`), the function is
# actually executed by the main thread, and no separate threads are ever created! 

argument = 1
arg2 = 2
newThread = threading.Thread(target=threading_function, args=(argument,arg2))
newThread.start()
newThread = threading.Thread(target=threading_function, args=(argument,arg2))
newThread.start()
newThread = threading.Thread(target=threading_function, args=(argument,arg2))
newThread.start()