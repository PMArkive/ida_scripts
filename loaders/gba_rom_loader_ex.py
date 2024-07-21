# Game Boy Advance ROM Loader for IDA 7.5
# Copyright (c) 2024 Daowen Sun (https://github.com/dnasdw)
# Version v1.0.0

# References:
#     https://github.com/SiD3W4y/GhidraGBA/blob/master/src/main/java/ghidragba/GhidraGBALoader.java
#     https://gist.github.com/thorodin-roth/b591807a90ee704fca22c677a566f0f0
#     https://github.com/laqieer/ida_gba_stuff/blob/master/loaders/GBA_Loader.py
#     https://github.com/JackBro/ida-gba-ldr/blob/master/gba.cpp
#     https://github.com/dnasdw/gbatools/blob/master/src/findwavedata/findwavedata.cpp

from collections import OrderedDict
import idaapi
import math
import struct

# BOOT ROM aka BIOS
BOOT_ROM_FORMAT_NAME = "Game Boy Advance Boot ROM: ARM7TDMI"

BOOT_ROM_DATA_28 = b"\x18\x00\x00\xEA\x04\x00\x00\xEA\x4C\x00\x00\xEA\x02\x00\x00\xEA\x01\x00\x00\xEA\x00\x00\x00\xEA\x42\x00\x00\xEA"

# SOFTWARE ROM
ROM_FORMAT_NAME = "Game Boy Advance ROM: ARM7TDMI + EX(but slow)"

ROM_HEADER_SIZE = 0xC0

NINTENDO_LOGO_CHARACTER_DATA_OFFSET = 0x4
NINTENDO_LOGO_CHARACTER_DATA_4 = b"\x24\xFF\xAE\x51"

FIXED_VALUE_OFFSET = 0xB2
FIXED_VALUE = b'\x96'

REG_BASE = 0x04000000

BOOT_ROM = 0x00000000
ROM = 0x08000000

# fix start_vector function range
fix_start_vector_enabled = 1

# set Number of opcode bytes = 4
# jump to _start
my_config_step_1_enabled = 1

# keep Text View
my_config_step_2_enabled = 1

current_rom = ROM

start_vector_start_offset = 0

widget_title_ignore = dict()

my_view_hook = None
my_idb_hook = None
my_ui_hook = None

s_nWaveDataSizeMax = 0xFFFF
s_sPackingAlgorithmAif2Agb_1_06a = "aif2agb_1.06a"
s_sPackingAlgorithmPok_Aif_1_06a_006 = "pok_aif_1.06a.006"

m_vFile = bytearray()
m_uFilePos = 0
m_nType = 0
m_nPlayMode = 0
m_nWaveDataUncompressedSize = 0
m_nWaveDataCompressedSize = 0
m_nWaveDataUncompressedLoopPosition = 0
m_nWaveDataCompressedLoopPosition = 0
m_nCompressedLastByte = 0


def lossyUncompressSoundDataAif2Agb106a():
    global m_vFile
    global m_uFilePos
    global m_nPlayMode
    global m_nWaveDataUncompressedSize
    global m_nWaveDataCompressedSize
    global m_nWaveDataUncompressedLoopPosition
    global m_nWaveDataCompressedLoopPosition
    global m_nCompressedLastByte

    bResult = True
    uFilePos = m_uFilePos + 16
    nUncompressedSize = 0
    nCompressedPos = 0

    while True:
        if m_nWaveDataCompressedSize - nCompressedPos < 1:
            break
        nFlags = m_vFile[uFilePos + nCompressedPos]
        nCompressedPos += 1
        nLengthMin = 1
        nLength = nFlags >> 6 & 0x3
        if nLength == 0:
            nLengthMin = 0x3 + 1
            nLength = nFlags & 0x3F
            if nLength <= 3:
                if m_nWaveDataCompressedSize - nCompressedPos < 1:
                    bResult = False
                    break
                nLengthMin = 0x3F + 1
                nLength = (nLength << 8) | (m_vFile[uFilePos + nCompressedPos] & 0xFF)
                nCompressedPos += 1
        if nLength < nLengthMin:
            bResult = False
            break
        if nLength > 3:
            if m_nWaveDataCompressedSize - nCompressedPos < 1:
                bResult = False
                break
            nCompressedPos += 1
        nUncompressedSize += nLength
    if not bResult:
        return False

    if nUncompressedSize > s_nWaveDataSizeMax:
        return False

    bFoundUncompressedLoopPosition = False
    if m_nPlayMode == 0:
        bFoundUncompressedLoopPosition = True
    nUncompressedPos = 0
    nPrevSample = 0
    nCompressedPos = 0

    while nUncompressedSize - nUncompressedPos > 0:
        if m_nWaveDataCompressedSize - nCompressedPos < 1:
            bResult = False
            break

        bFoundCompressedLoopPosition = False
        if not bFoundUncompressedLoopPosition:
            if nCompressedPos == m_nWaveDataCompressedLoopPosition:
                bFoundCompressedLoopPosition = True
            elif nCompressedPos > m_nWaveDataCompressedLoopPosition:
                bResult = False
                break

        nFlags = m_vFile[uFilePos + nCompressedPos]
        nCompressedPos += 1
        nLengthMin = 1
        nLength = nFlags >> 6 & 0x3
        nCurrSample = 0

        if nLength == 0:
            nLengthMin = 0x3 + 1
            nLength = nFlags & 0x3F
            if nLength <= 3:
                if m_nWaveDataCompressedSize - nCompressedPos < 1:
                    bResult = False
                    break
                nLengthMin = 0x3F + 1
                nLength = (nLength << 8) | (m_vFile[uFilePos + nCompressedPos] & 0xFF)
                nCompressedPos += 1
        if nLength < nLengthMin:
            bResult = False
            break

        if nLength <= 3:
            nCompressedDelta = nFlags & 0x3F
            if (nCompressedDelta & 0x20) != 0:
                nCompressedDelta |= 0xFFFFFFC0
            nCompressedDelta = struct.unpack("<i", struct.pack("<I", nCompressedDelta))[0]
            nDelta = 0
            if nCompressedDelta < 0:
                nDelta = -(int(pow(-nCompressedDelta, 1.6)) << 8)
            else:
                nDelta = int(pow(nCompressedDelta, 1.6)) << 8
            nCurrSample = nPrevSample + nDelta
        else:
            if m_nWaveDataCompressedSize - nCompressedPos < 1:
                bResult = False
                break
            nCurrSample = m_vFile[uFilePos + nCompressedPos] << 8
            nCompressedPos += 1

        if (nCurrSample & 0x8000) != 0:
            nCurrSample |= 0xFFFF0000
        nCurrSample = struct.unpack("<i", struct.pack("<I", nCurrSample & 0xFFFFFFFF))[0]

        if nLength > nUncompressedSize - nUncompressedPos:
            bResult = False
            break

        nUncompressedPos += nLength

        if bFoundCompressedLoopPosition:
            bFoundUncompressedLoopPosition = True
            m_nWaveDataUncompressedLoopPosition = nUncompressedPos - 1
            m_nCompressedLastByte = nPrevSample >> 8

        nPrevSample = nCurrSample

    if bResult:
        nLastByte = 0
        if m_nPlayMode != 0:
            nLastByte = m_nCompressedLastByte

        if m_vFile[uFilePos + m_nWaveDataCompressedSize] != nLastByte & 0xFF:
            bFoundUncompressedLoopPosition = False
            m_nWaveDataUncompressedLoopPosition = m_nWaveDataCompressedLoopPosition

        if not bFoundUncompressedLoopPosition or nUncompressedPos != nUncompressedSize or nCompressedPos != m_nWaveDataCompressedSize:
            bResult = False
    if not bResult:
        return False

    m_nWaveDataUncompressedSize = nUncompressedSize
    return True


class SWaveDataHeader:
    def __init__(self):
        self.Type = 0
        self.Stat = 0
        self.Freq = 0
        self.Loop = 0
        self.Size = 0


def get_arm_branch_offset(branch_inst):
    offset = branch_inst & 0xFFFFFF
    if offset >> 23 & 1 == 1:
        offset |= 0xFF000000
    offset = offset << 2 & 0xFFFFFFFF
    offset = struct.unpack("<i", struct.pack("<I", offset))[0]
    offset += 8
    return offset


def fix_start_vector():
    if fix_start_vector_enabled:
        if current_rom == ROM:
            # print(f"gba::fix_start_vector: start_vector_start_offset = 0x{start_vector_start_offset:X}")
            start_vector_end_offset = idaapi.BADADDR
            pfn: idaapi.func_t = idaapi.get_func(ROM + start_vector_start_offset)
            end_ea = pfn.end_ea
            # print(f"gba::fix_start_vector: end_ea = 0x{end_ea:X}")

            if start_vector_end_offset == idaapi.BADADDR:
                branch_inst = idaapi.get_32bit(end_ea)
                # print(f"gba::fix_start_vector: branch_inst = 0x{branch_inst:08X}")
                if branch_inst & 0x0F000000 == 0x0A000000:
                    branch_offset = get_arm_branch_offset(branch_inst)
                    branch_offset += end_ea - ROM
                    # print(f"gba::fix_start_vector: branch_offset: 0x{branch_offset:X}")
                    if branch_offset == start_vector_start_offset:
                        start_vector_end_offset = end_ea - ROM + 4
                        # print(f"gba::fix_start_vector: start_vector_end_offset = 0x{start_vector_end_offset:X}")

            if start_vector_end_offset == idaapi.BADADDR:
                ea = idaapi.get_next_cref_to(ROM + start_vector_start_offset, end_ea - 1)
                # print(f"gba::fix_start_vector: ea = 0x{ea:X}")
                if ea != idaapi.BADADDR:
                    start_vector_end_offset = ea - ROM + 4
                    # print(f"gba::fix_start_vector: start_vector_end_offset = 0x{start_vector_end_offset:X}")

            if start_vector_end_offset != idaapi.BADADDR:
                idaapi.del_func(ROM + start_vector_start_offset)
                idaapi.add_func(ROM + start_vector_start_offset, ROM + start_vector_end_offset)


def my_config_step_1():
    if my_config_step_1_enabled:
        idaapi.inf_set_bin_prefix_size(4)
        idaapi.jumpto(current_rom)


def my_config_step_2():
    if my_config_step_2_enabled:
        for widget_title, ignore in widget_title_ignore.items():
            # print(f"gba::my_config_step_2: ignore[{widget_title}] = {ignore}")
            if ignore:
                continue
            w = idaapi.find_widget(widget_title)
            # print(f"gba::my_config_step_2: {widget_title} {w} {idaapi.get_widget_type(w)} {idaapi.get_view_renderer_type(w)}")
            if idaapi.get_widget_type(w) == idaapi.BWN_DISASM:
                idaapi.set_view_renderer_type(w, idaapi.TCCRT_FLAT)


class MyViewHook(idaapi.View_Hooks):
    def hook(self, *args):
        print("gba::MyViewHook installed")
        return super().hook(*args)

    def unhook(self, *args):
        print("gba::MyViewHook uninstalled")
        return super().unhook(*args)

    def view_created(self, view, *args):
        widget_title = idaapi.get_widget_title(view)
        widget_title_ignore[widget_title] = False
        # print(f"gba::view_created: ignore[{widget_title}] = {widget_title_ignore[widget_title]}")
        return super().view_created(view, *args)

    def view_close(self, view, *args):
        widget_title = idaapi.get_widget_title(view)
        # print(f"gba::view_close: {widget_title}")
        del widget_title_ignore[widget_title]
        return super().view_close(view, *args)

    def view_switched(self, view, rt, *args):
        widget_title = idaapi.get_widget_title(view)
        # print(f"gba::view_switched: {widget_title} {rt}")
        if rt == idaapi.TCCRT_GRAPH:
            widget_title_ignore[widget_title] = True
        elif rt == idaapi.TCCRT_FLAT:
            widget_title_ignore[widget_title] = False
        # print(f"gba::view_switched: ignore[{widget_title}] = {widget_title_ignore[widget_title]}")
        return super().view_switched(view, rt, *args)


class MyIDBHook(idaapi.IDB_Hooks):
    def hook(self, *args):
        print("gba::MyIDBHook installed")
        return super().hook(*args)

    def unhook(self, *args):
        print("gba::MyIDBHook uninstalled")
        return super().unhook(*args)

    def auto_empty_finally(self, *args):
        global my_view_hook
        global my_idb_hook
        global my_ui_hook
        if my_view_hook != None:
            my_view_hook.unhook()
            my_view_hook = None
        if my_idb_hook != None:
            my_idb_hook.unhook()
            my_idb_hook = None
        if my_ui_hook != None:
            my_ui_hook.unhook()
            my_ui_hook = None
        idaapi.execute_ui_requests((fix_start_vector, my_config_step_2))
        return super().auto_empty_finally(*args)


class MyUIHook(idaapi.UI_Hooks):
    def hook(self, *args):
        print("gba::MyUIHook installed")
        return super().hook(*args)

    def unhook(self, *args):
        print("gba::MyUIHook uninstalled")
        return super().unhook(*args)

    def database_closed(self, *args):
        global my_view_hook
        global my_idb_hook
        global my_ui_hook
        if my_view_hook != None:
            my_view_hook.unhook()
            my_view_hook = None
        if my_idb_hook != None:
            my_idb_hook.unhook()
            my_idb_hook = None
        if my_ui_hook != None:
            my_ui_hook.unhook()
            my_ui_hook = None
        return super().database_closed(*args)


def accept_file(li: idaapi.loader_input_t, filename):
    size = li.size()
    if size < ROM_HEADER_SIZE:
        return 0

    if size == 0x4000 and li.read(28) == BOOT_ROM_DATA_28:
        return {"format": BOOT_ROM_FORMAT_NAME, "processor": "arm"}

    li.seek(0)
    branch_inst = struct.unpack("<I", li.read(4))[0]
    if branch_inst & 0x0F000000 != 0x0A000000:
        return 0

    branch_offset = get_arm_branch_offset(branch_inst)
    if branch_offset < ROM_HEADER_SIZE or branch_offset >= size:
        return 0

    li.seek(NINTENDO_LOGO_CHARACTER_DATA_OFFSET)
    if li.read(4) != NINTENDO_LOGO_CHARACTER_DATA_4:
        return 0

    li.seek(FIXED_VALUE_OFFSET)
    if li.read(1) != FIXED_VALUE:
        return 0

    return {"format": ROM_FORMAT_NAME, "processor": "arm"}


def add_seg(start_ea, size, name, use32, cls="DATA", patch_byte=None):
    s = idaapi.segment_t()
    s.start_ea = start_ea
    s.end_ea = start_ea + size
    s.sel = idaapi.setup_selector(0)
    s.bitness = use32
    s.align = idaapi.saRelPara
    s.comb = idaapi.scPub

    if cls == "CODE":
        s.type = idaapi.SEG_CODE
    else:
        s.type = idaapi.SEG_DATA

    if cls == "CODE":
        s.perm = idaapi.SEGPERM_READ | idaapi.SEGPERM_EXEC
    else:
        s.perm = idaapi.SEGPERM_READ | idaapi.SEGPERM_WRITE | idaapi.SEGPERM_EXEC

    idaapi.add_segm_ex(s, name, cls, idaapi.ADDSEG_NOSREG | idaapi.ADDSEG_OR_DIE)
    if patch_byte != None:
        idaapi.patch_bytes(start_ea, bytes([patch_byte] * size))


def create_data_label(ea, size, name, type=-1):
    if type == -1:
        type = size

    dataflag = idaapi.FF_BYTE
    if type == 0:
        dataflag = idaapi.FF_STRLIT
    elif type == 1:
        dataflag = idaapi.FF_BYTE
    elif type == 2:
        dataflag = idaapi.FF_WORD
    elif type == 4:
        dataflag = idaapi.FF_DWORD

    idaapi.create_data(ea, dataflag, size, idaapi.BADNODE)
    idaapi.set_name(ea, name, idaapi.SN_NOCHECK)


def load_file(li: idaapi.loader_input_t, neflags, format):
    if format != ROM_FORMAT_NAME and format != BOOT_ROM_FORMAT_NAME:
        idaapi.warning(f"Unknown format name: '{format}'")
        return 0

    idaapi.set_processor_type("arm:armv4t", idaapi.SETPROC_LOADER | idaapi.SETPROC_LOADER_NON_FATAL)
    # GNU assembler
    idaapi.set_target_assembler(1)

    size = li.size()
    print(f"file size 0x{size:08X}")

    global current_rom
    global start_vector_start_offset
    if format == ROM_FORMAT_NAME:
        current_rom = ROM
        branch_inst = struct.unpack("<I", li.read(4))[0]
        start_vector_start_offset = get_arm_branch_offset(branch_inst)
    elif format == BOOT_ROM_FORMAT_NAME:
        current_rom = BOOT_ROM

    # depends on current_rom
    idaapi.execute_ui_requests((my_config_step_1,))

    global my_view_hook
    my_view_hook = MyViewHook()
    my_view_hook.hook()
    global my_idb_hook
    my_idb_hook = MyIDBHook()
    my_idb_hook.hook()
    global my_ui_hook
    my_ui_hook = MyUIHook()
    my_ui_hook.hook()

    try:
        if format == ROM_FORMAT_NAME:
            # do_not_add_seg(0x00000000, 0x4000, "BIOS", 1, "CODE", patch_byte=0)
            pass
        elif format == BOOT_ROM_FORMAT_NAME:
            add_seg(0x00000000, 0x4000, "BIOS", 1, "CODE")

        add_seg(0x02000000, 0x40000, "EWRAM", 0, patch_byte=0)
        add_seg(0x03000000, 0x8000, "IWRAM", 1, patch_byte=0)
        add_seg(0x04000000, 0x400, "REG", 1, patch_byte=0)
        add_seg(0x05000000, 0x400, "PLTT", 0, patch_byte=0)
        add_seg(0x06000000, 0x18000, "VRAM", 0, patch_byte=0)
        add_seg(0x07000000, 0x400, "OAM", 1, patch_byte=0)
        add_seg(0x08000000, 0x2000000, "ROM", 1, "CODE")

        if format == BOOT_ROM_FORMAT_NAME:
            idaapi.patch_bytes(ROM, bytes([0] * ROM_HEADER_SIZE))

        create_data_label(REG_BASE + 0x0, 2, "REG_DISPCNT")
        create_data_label(REG_BASE + 0x4, 2, "REG_DISPSTAT")
        create_data_label(REG_BASE + 0x6, 2, "REG_VCOUNT")
        create_data_label(REG_BASE + 0x8, 2, "REG_BG0CNT")
        create_data_label(REG_BASE + 0xA, 2, "REG_BG1CNT")
        create_data_label(REG_BASE + 0xC, 2, "REG_BG2CNT")
        create_data_label(REG_BASE + 0xE, 2, "REG_BG3CNT")
        create_data_label(REG_BASE + 0x10, 2, "REG_BG0HOFS")
        create_data_label(REG_BASE + 0x12, 2, "REG_BG0VOFS")
        create_data_label(REG_BASE + 0x14, 2, "REG_BG1HOFS")
        create_data_label(REG_BASE + 0x16, 2, "REG_BG1VOFS")
        create_data_label(REG_BASE + 0x18, 2, "REG_BG2HOFS")
        create_data_label(REG_BASE + 0x1A, 2, "REG_BG2VOFS")
        create_data_label(REG_BASE + 0x1C, 2, "REG_BG3HOFS")
        create_data_label(REG_BASE + 0x1E, 2, "REG_BG3VOFS")
        create_data_label(REG_BASE + 0x20, 2, "REG_BG2PA")
        create_data_label(REG_BASE + 0x22, 2, "REG_BG2PB")
        create_data_label(REG_BASE + 0x24, 2, "REG_BG2PC")
        create_data_label(REG_BASE + 0x26, 2, "REG_BG2PD")
        create_data_label(REG_BASE + 0x28, 4, "REG_BG2X")
        create_data_label(REG_BASE + 0x2C, 4, "REG_BG2Y")
        create_data_label(REG_BASE + 0x30, 2, "REG_BG3PA")
        create_data_label(REG_BASE + 0x32, 2, "REG_BG3PB")
        create_data_label(REG_BASE + 0x34, 2, "REG_BG3PC")
        create_data_label(REG_BASE + 0x36, 2, "REG_BG3PD")
        create_data_label(REG_BASE + 0x38, 4, "REG_BG3X")
        create_data_label(REG_BASE + 0x3C, 4, "REG_BG3Y")
        create_data_label(REG_BASE + 0x40, 2, "REG_WIN0H")
        create_data_label(REG_BASE + 0x42, 2, "REG_WIN1H")
        create_data_label(REG_BASE + 0x44, 2, "REG_WIN0V")
        create_data_label(REG_BASE + 0x46, 2, "REG_WIN1V")
        create_data_label(REG_BASE + 0x48, 2, "REG_WININ")
        create_data_label(REG_BASE + 0x4A, 2, "REG_WINOUT")
        create_data_label(REG_BASE + 0x4C, 2, "REG_MOSAIC")
        create_data_label(REG_BASE + 0x50, 2, "REG_BLDCNT")
        create_data_label(REG_BASE + 0x52, 2, "REG_BLDALPHA")
        create_data_label(REG_BASE + 0x54, 2, "REG_BLDY")
        create_data_label(REG_BASE + 0x60, 2, "REG_SOUND1CNT_L")
        create_data_label(REG_BASE + 0x62, 2, "REG_SOUND1CNT_H")
        create_data_label(REG_BASE + 0x64, 2, "REG_SOUND1CNT_X")
        create_data_label(REG_BASE + 0x68, 2, "REG_SOUND2CNT_L")
        create_data_label(REG_BASE + 0x6C, 2, "REG_SOUND2CNT_H")
        create_data_label(REG_BASE + 0x70, 2, "REG_SOUND3CNT_L")
        create_data_label(REG_BASE + 0x72, 2, "REG_SOUND3CNT_H")
        create_data_label(REG_BASE + 0x74, 2, "REG_SOUND3CNT_X")
        create_data_label(REG_BASE + 0x78, 2, "REG_SOUND4CNT_L")
        create_data_label(REG_BASE + 0x7C, 2, "REG_SOUND4CNT_H")
        create_data_label(REG_BASE + 0x80, 2, "REG_SOUNDCNT_L")
        create_data_label(REG_BASE + 0x82, 2, "REG_SOUNDCNT_H")
        create_data_label(REG_BASE + 0x84, 2, "REG_SOUNDCNT_X")
        create_data_label(REG_BASE + 0x88, 2, "REG_SOUNDBIAS")
        create_data_label(REG_BASE + 0x90, 4, "REG_WAVE_RAM0")
        create_data_label(REG_BASE + 0x94, 4, "REG_WAVE_RAM1")
        create_data_label(REG_BASE + 0x98, 4, "REG_WAVE_RAM2")
        create_data_label(REG_BASE + 0x9C, 4, "REG_WAVE_RAM3")
        create_data_label(REG_BASE + 0xA0, 4, "REG_FIFO_A")
        create_data_label(REG_BASE + 0xA4, 4, "REG_FIFO_B")
        create_data_label(REG_BASE + 0xB0, 4, "REG_DMA0SAD")
        create_data_label(REG_BASE + 0xB4, 4, "REG_DMA0DAD")
        create_data_label(REG_BASE + 0xB8, 2, "REG_DMA0CNT_L")
        create_data_label(REG_BASE + 0xBA, 2, "REG_DMA0CNT_H")
        create_data_label(REG_BASE + 0xBC, 4, "REG_DMA1SAD")
        create_data_label(REG_BASE + 0xC0, 4, "REG_DMA1DAD")
        create_data_label(REG_BASE + 0xC4, 2, "REG_DMA1CNT_L")
        create_data_label(REG_BASE + 0xC6, 2, "REG_DMA1CNT_H")
        create_data_label(REG_BASE + 0xC8, 4, "REG_DMA2SAD")
        create_data_label(REG_BASE + 0xCC, 4, "REG_DMA2DAD")
        create_data_label(REG_BASE + 0xD0, 2, "REG_DMA2CNT_L")
        create_data_label(REG_BASE + 0xD2, 2, "REG_DMA2CNT_H")
        create_data_label(REG_BASE + 0xD4, 4, "REG_DMA3SAD")
        create_data_label(REG_BASE + 0xD8, 4, "REG_DMA3DAD")
        create_data_label(REG_BASE + 0xDC, 2, "REG_DMA3CNT_L")
        create_data_label(REG_BASE + 0xDE, 2, "REG_DMA3CNT_H")
        create_data_label(REG_BASE + 0x100, 2, "REG_TM0CNT_L")
        create_data_label(REG_BASE + 0x102, 2, "REG_TM0CNT_H")
        create_data_label(REG_BASE + 0x104, 2, "REG_TM1CNT_L")
        create_data_label(REG_BASE + 0x106, 2, "REG_TM1CNT_H")
        create_data_label(REG_BASE + 0x108, 2, "REG_TM2CNT_L")
        create_data_label(REG_BASE + 0x10A, 2, "REG_TM2CNT_H")
        create_data_label(REG_BASE + 0x10C, 2, "REG_TM3CNT_L")
        create_data_label(REG_BASE + 0x10E, 2, "REG_TM3CNT_H")
        create_data_label(REG_BASE + 0x120, 2, "REG_SIOMULTI0")
        create_data_label(REG_BASE + 0x122, 2, "REG_SIOMULTI1")
        create_data_label(REG_BASE + 0x124, 2, "REG_SIOMULTI2")
        create_data_label(REG_BASE + 0x126, 2, "REG_SIOMULTI3")
        create_data_label(REG_BASE + 0x128, 2, "REG_SIOCNT")
        create_data_label(REG_BASE + 0x12A, 2, "REG_SIODATA8")
        create_data_label(REG_BASE + 0x130, 2, "REG_KEYINPUT")
        create_data_label(REG_BASE + 0x132, 2, "REG_KEYCNT")
        create_data_label(REG_BASE + 0x134, 2, "REG_RCNT")
        create_data_label(REG_BASE + 0x140, 2, "REG_JOYCNT")
        create_data_label(REG_BASE + 0x150, 4, "REG_JOY_RECV")
        create_data_label(REG_BASE + 0x154, 4, "REG_JOY_TRANS")
        create_data_label(REG_BASE + 0x158, 2, "REG_JOYSTAT")
        create_data_label(REG_BASE + 0x200, 2, "REG_IE")
        create_data_label(REG_BASE + 0x202, 2, "REG_IF")
        create_data_label(REG_BASE + 0x204, 2, "REG_WAITCNT")
        create_data_label(REG_BASE + 0x208, 2, "REG_IME")
        create_data_label(REG_BASE + 0x300, 1, "REG_END")

        if format == ROM_FORMAT_NAME:
            global m_vFile
            global m_uFilePos
            global m_nType
            global m_nPlayMode
            global m_nWaveDataUncompressedSize
            global m_nWaveDataCompressedSize
            global m_nWaveDataUncompressedLoopPosition
            global m_nWaveDataCompressedLoopPosition
            global m_nCompressedLastByte

            li.seek(0)
            m_vFile = li.read(size)

            sFreq = set()
            for i in range(math.ceil((180 - 128) / 12.0), 180 // 12 + 1):
                for base in [5734, 7884, 10512, 13379, 15768, 18157, 21024, 26758, 31536, 36314, 40137, 42048]:
                    sFreq.add(base << i)

            mOffsetSize0 = dict()
            mOffsetSize1 = dict()
            sValidBeginOffset = set()
            m_uFilePos = 0
            while m_uFilePos + 16 <= size:
                pWaveDataHeader = SWaveDataHeader()
                (pWaveDataHeader.Type, pWaveDataHeader.Stat, pWaveDataHeader.Freq, pWaveDataHeader.Loop, pWaveDataHeader.Size) = struct.unpack_from("<HHIII", m_vFile, m_uFilePos)

                if pWaveDataHeader.Type != 0 and pWaveDataHeader.Type != 1:
                    m_uFilePos += 4
                    continue
                if pWaveDataHeader.Stat != 0 and pWaveDataHeader.Stat != 0x4000:
                    m_uFilePos += 4
                    continue
                bFoundFreq = pWaveDataHeader.Freq in sFreq
                if pWaveDataHeader.Stat == 0 and pWaveDataHeader.Loop != 0:
                    m_uFilePos += 4
                    continue
                if struct.unpack("<i", struct.pack("<I", pWaveDataHeader.Loop))[0] < 0 or struct.unpack("<i", struct.pack("<I", pWaveDataHeader.Size))[0] < 0:
                    m_uFilePos += 4
                    continue
                if pWaveDataHeader.Loop >= pWaveDataHeader.Size:
                    m_uFilePos += 4
                    continue
                if pWaveDataHeader.Size > s_nWaveDataSizeMax:
                    m_uFilePos += 4
                    continue

                m_nType = pWaveDataHeader.Type
                m_nPlayMode = pWaveDataHeader.Stat >> 14 & 0x3
                m_nWaveDataCompressedLoopPosition = pWaveDataHeader.Loop
                m_nWaveDataCompressedSize = pWaveDataHeader.Size
                m_nWaveDataUncompressedLoopPosition = pWaveDataHeader.Loop
                m_nWaveDataUncompressedSize = pWaveDataHeader.Size

                sAlgorithm = ""
                if m_nType == 1:
                    vAlgorithm = [s_sPackingAlgorithmAif2Agb_1_06a, s_sPackingAlgorithmPok_Aif_1_06a_006]
                    bFound = False
                    for sAlgorithm in vAlgorithm:
                        if sAlgorithm == s_sPackingAlgorithmPok_Aif_1_06a_006:
                            nPaddingCount = 1
                            nCompressedSize = (m_nWaveDataUncompressedSize + nPaddingCount) // 64 * 33
                            nRemainder = (m_nWaveDataUncompressedSize + nPaddingCount) % 64
                            if nRemainder <= 2:
                                nCompressedSize += nRemainder
                            else:
                                nPaddingCount = 1 if (nRemainder - 2) % 2 == 0 else 0
                                nCompressedSize += 2 + (nRemainder - 2) // 2
                            if m_uFilePos + 16 + nCompressedSize > size:
                                continue
                            m_nWaveDataCompressedSize = nCompressedSize
                            bFound = True
                        elif sAlgorithm == s_sPackingAlgorithmAif2Agb_1_06a:
                            if m_uFilePos + 16 + m_nWaveDataCompressedSize + 1 > size:
                                continue
                            if not lossyUncompressSoundDataAif2Agb106a():
                                continue
                            bFound = True
                        if bFound:
                            break
                    if not bFound:
                        m_uFilePos += 4
                        continue
                elif m_nType == 0:
                    if m_uFilePos + 16 + m_nWaveDataUncompressedSize + 1 > size:
                        m_uFilePos += 4
                        continue
                    sAlgorithm = s_sPackingAlgorithmAif2Agb_1_06a

                uFilePos = m_uFilePos + 16
                if sAlgorithm != s_sPackingAlgorithmPok_Aif_1_06a_006 or m_nType == 0:
                    if m_uFilePos + 16 + m_nWaveDataCompressedSize + 1 > size:
                        m_uFilePos += 4
                        continue
                    nLastByte = 0
                    if m_nPlayMode != 0:
                        if m_nType == 0:
                            nLastByte = m_vFile[m_uFilePos + 16 + m_nWaveDataUncompressedLoopPosition]
                        else:
                            nLastByte = m_nCompressedLastByte
                    if m_vFile[m_uFilePos + 16 + m_nWaveDataCompressedSize] != nLastByte & 0xFF:
                        m_uFilePos += 4
                        continue
                    uFilePos += m_nWaveDataCompressedSize + 1
                else:
                    uFilePos += m_nWaveDataCompressedSize

                bAligned = True
                nPaddingCount = (4 - uFilePos % 4) % 4
                if uFilePos == size:
                    nPaddingCount = 0
                if uFilePos + nPaddingCount > size:
                    m_uFilePos += 4
                    continue
                for i in range(nPaddingCount):
                    if m_vFile[uFilePos + i] != 0:
                        bAligned = False
                        break
                if not bAligned:
                    m_uFilePos += 4
                    continue

                if bFoundFreq:
                    mOffsetSize0[m_uFilePos] = uFilePos - m_uFilePos
                    sValidBeginOffset.add(uFilePos + nPaddingCount)
                else:
                    mOffsetSize1[m_uFilePos] = uFilePos - m_uFilePos
                    m_uFilePos += 4
                    continue
                m_uFilePos = uFilePos + nPaddingCount

            mOffsetSize1 = OrderedDict(sorted(mOffsetSize1.items()))

            for uOffset, uSize in mOffsetSize1.items():
                m_uFilePos = uOffset
                if m_uFilePos in sValidBeginOffset:
                    uFilePos = m_uFilePos + uSize
                    nPaddingCount = (4 - uFilePos % 4) % 4
                    if uFilePos == size:
                        nPaddingCount = 0
                    mOffsetSize0[m_uFilePos] = uFilePos - m_uFilePos
                    sValidBeginOffset.add(uFilePos + nPaddingCount)

            mOffsetSize0 = OrderedDict(sorted(mOffsetSize0.items()))

            for uOffset, uSize in mOffsetSize0.items():
                create_data_label(ROM + uOffset, uSize, f"DirectSound_{ROM + uOffset:X}", 1)

        li.file2base(0, current_rom, current_rom + size, True)
        idaapi.add_func(current_rom)
        idaapi.add_entry(current_rom, current_rom, "_start", True)

        create_data_label(ROM + NINTENDO_LOGO_CHARACTER_DATA_OFFSET, 0x9C, "Nintendo Logo Character Data", 1)
        create_data_label(ROM + 0xA0, 0xC, "Software Title", 0)
        create_data_label(ROM + 0xAC, 0x4, "Initial Code", 0)
        create_data_label(ROM + 0xB0, 0x2, "Maker Code", 0)
        create_data_label(ROM + FIXED_VALUE_OFFSET, 0x1, "Fixed Value", 1)
        create_data_label(ROM + 0xB3, 0x1, "Main Unit Code", 1)
        create_data_label(ROM + 0xB4, 0x1, "Device Type", 1)
        create_data_label(ROM + 0xB5, 0x7, "Unused Data", 1)
        create_data_label(ROM + 0xBC, 0x1, "Software Version No", 1)
        create_data_label(ROM + 0xBD, 0x1, "Complement Check", 1)
        create_data_label(ROM + 0xBE, 0x2, "Checksum", 1)

        if format == ROM_FORMAT_NAME:
            if start_vector_start_offset != ROM_HEADER_SIZE:
                create_data_label(ROM + ROM_HEADER_SIZE, start_vector_start_offset - ROM_HEADER_SIZE, "custom header", 1)

            idaapi.add_func(ROM + start_vector_start_offset)
            idaapi.set_name(ROM + start_vector_start_offset, "start_vector", idaapi.SN_NOCHECK)
        else:
            idaapi.add_func(0x4)
            idaapi.add_func(0x8)
            idaapi.add_func(0xC)
            idaapi.add_func(0x10)
            idaapi.add_func(0x14)
            idaapi.add_func(0x18)

        return 1
    except Exception as e:
        print(e)
        return 0
