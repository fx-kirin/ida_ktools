"""ida_ktools - ''"""
import ctypes
import logging
import re

import idc
import logzero
import redis
from ida_bytes import *
from idautils import _cpu

__version__ = "0.1.0"
__author__ = "fx-kirin <ono.kirin@gmail.com>"


connection = redis.StrictRedis(host="localhost", port=6379, db=0)

cpu = _cpu()


def redis_get(name):
    return connection.get(name)


def redis_set(name, value):
    return connection.set(name, value)


def memcpy(dest, src, start_from, length):
    return dest[:start_from] + src[:length] + dest[start_from + length:]


def null_string(size):
    return "\x00" * size


def log_call_parameter(arg_length=4, start_from=4):
    info("------------ Log Call 0x%x --------------- " % (cpu.eip))
    info("ecx :%x" % (cpu.ecx))
    for i in range(arg_length):
        info("arg%d :0x%x" % (i + 1, get_32bit(cpu.esp + start_from + 4 * i)))


def info(text, *args):
    logging.info("|0x%x|" % (cpu.eip) + text, *args)
    

def log_operands():
    dsm = idc.GetDisasm(cpu.eip)
    info(f"{dsm}")
    for i in range(2):
        op_type = idc.get_operand_type(cpu.eip, i)
        if op_type > 0:
            if op_type == 1:
                register = idc.print_operand(cpu.eip, i)
                value = idc.get_reg_value(register)
                info(f"register:{register} op{i}:0x{value:x}")
            elif op_type == 4:
                register = idc.print_operand(cpu.eip, i)
                register = re.match(r"\[(\w*)\+(.*)\]", register).group(1)
                value = ctypes.c_int32(idc.get_operand_value(cpu.eip, i)).value
                address = getattr(cpu, register) + value
                value = get_32bit(address)
                info(f"address:0x{address:x} op{i}:0x{value:x}")


logzero.__name__ = ""
logzero.setup_logger("", formatter=logzero.LogFormatter(color=False))
