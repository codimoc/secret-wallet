import os

def touch(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'a'):
        os.utime(path, None)