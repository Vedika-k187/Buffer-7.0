from queue import Queue

# Global queue that the entire system shares
dns_queue = Queue()

def add_to_queue(record):
    dns_queue.put(record)

def get_from_queue():
    return dns_queue.get()

def queue_size():
    return dns_queue.qsize()

def is_empty():
    return dns_queue.empty()