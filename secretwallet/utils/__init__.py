import sys
def make_version_number(v:sys.version_info)-> int :
    return v.major*1000+v.minor*100+v.micro