"""ida_ktools - ''"""

__version__ = '0.1.0'
__author__ = 'fx-kirin <ono.kirin@gmail.com>'

import redis
import ida_bytes
connection = redis.StrictRedis(host='localhost', port=6379, db=0)

def redis_get(name):
    connection.get(name)

def redis_set(name, value):
    connection.get(name, value)

def memcpy(dest, src, start_from, length):
    return dest[:start_from] + src[:length] + dest[start_from+length:]

def null_string(size):
    return '\x00' * size

def get_bytes(pointer, length):
    return ida_bytes.get_bytes(pointer, length)

def get_32bit(pointer):
    return ida_bytes.get_32bit(pointer)


