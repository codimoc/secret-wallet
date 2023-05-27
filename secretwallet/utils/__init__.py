import sys
import os

def make_version_number()-> int :
    v = sys.version_info
    return v.major*1000+v.minor*100+v.micro

def is_posix()->bool:
    return os.name=='posix'