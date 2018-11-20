"""ida_ktools - ''"""

__version__ = '0.1.0'
__author__ = 'fx-kirin <ono.kirin@gmail.com>'

import redis
import ida_bytes
connection = redis.StrictRedis(host='localhost', port=6379, db=0)

def redis_get(name):
    return connection.get(name)

def redis_set(name, value):
    return connection.set(name, value)

def memcpy(dest, src, start_from, length):
    return dest[:start_from] + src[:length] + dest[start_from+length:]

def null_string(size):
    return '\x00' * size

def get_bytes(pointer, length):
    return ida_bytes.get_bytes(pointer, length)

def get_32bit(pointer):
    return ida_bytes.get_32bit(pointer)

def log_call_parameter(arg_length=4, start_from=4):
    print("------------ Log Call 0x%x --------------- "%(cpu.eip))
    print('ecx :%x'%(cpu.ecx))
    for i in range(arg_length):
        print('arg%d :0x%x'%(i+1, ida_bytes.get_32bit(cpu.esp+start_from+4*i)))

