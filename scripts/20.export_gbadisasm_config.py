# export gbadisasm config for IDA 7.5
# Copyright (c) 2024 Daowen Sun (https://github.com/dnasdw)

# References:
#     https://github.com/laqieer/ida_gba_stuff/blob/master/idc/export_gbadisasm_config.idc
#     https://github.com/jiangzhengwenjz/gba_ida_util/blob/master/idc/export_cfg.idc

import idaapi
import idautils
import idc


def main():
    cfg_path = idaapi.get_input_file_path()
    index = cfg_path.rfind('.')
    if index != -1:
        cfg_path = cfg_path[:index] + ".cfg"
    else:
        cfg_path += ".cfg"

    with open(cfg_path, "w") as f:
        for ea in idautils.Functions():
            is_thumb = idc.get_sreg(ea, "T") != 0
            func_name = idaapi.get_func_name(ea)
            if is_thumb:
                f.write(f"thumb_func 0x{ea:x} {func_name}\n")
            else:
                f.write(f"arm_func 0x{ea:x} {func_name}\n")

    print(f"Exported to {cfg_path}")


main()
