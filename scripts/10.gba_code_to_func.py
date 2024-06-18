# gba code to function for IDA 7.5
# Copyright (c) 2024 Daowen Sun (https://github.com/dnasdw)

# References:
#     https://github.com/laqieer/ida_gba_stuff/blob/master/idc/add_undetected_functions.idc
#     https://github.com/jiangzhengwenjz/gba_ida_util/blob/master/idc/quick_func_scan.idc

import idaapi
import idc

ROM_SIZE_MAX = 0x02000000
ROM = 0x08000000
ROM_END = ROM + ROM_SIZE_MAX


def main():
    while True:
        func_count_old = idaapi.get_func_qty()
        ea = ROM
        while True:
            ea = idaapi.find_code(ea - 1, idaapi.SEARCH_DOWN)
            if ea == idaapi.BADADDR or ea >= ROM_END:
                break
            end_ea = ea
            func_name = idaapi.get_func_name(ea)
            # print(f"gba::code2func: / ea: 0x{ea:X} func_name: {func_name}")
            if func_name != None:
                end_ea = idc.get_func_attr(ea, idc.FUNCATTR_END)
            elif idaapi.add_func(ea):
                idaapi.auto_wait()
                func_name = idaapi.get_func_name(ea)
                print(f"gba::code2func: + ea: 0x{ea:X} func_name: {func_name}")
                end_ea = idc.get_func_attr(ea, idc.FUNCATTR_END)
            if end_ea > ea:
                ea = end_ea
            else:
                ea += 2
            # print(f"gba::code2func: \\ ea: 0x{ea:X}")

        func_count_new = idaapi.get_func_qty()
        # print(f"gba::code2func: func_count_old: {func_count_old}")
        # print(f"gba::code2func: func_count_new: {func_count_new}")
        if func_count_new == func_count_old:
            break

    print("gba::code2func: Done!")


main()
