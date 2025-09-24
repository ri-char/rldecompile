import asyncio
import os
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


async def add_string_symbols(filepath: str | Path):
    symbol_base_name = (
        "decgstr_" + os.path.basename(str(filepath)).removesuffix(".o") + "_"
    )
    with open(filepath, "rb") as f:  # noqa: ASYNC230
        elffile = ELFFile(f)
        target_sections = {}
        for section_id in range(elffile.num_sections()):
            section = elffile.get_section(section_id)
            if section.name.startswith(".rodata.str"):
                target_sections[section_id] = section
        symbol_tables = [
            s for s in elffile.iter_sections() if isinstance(s, SymbolTableSection)
        ]
        objcopy_args = []
        for symtab in symbol_tables:
            for symbol in symtab.iter_symbols():
                shndx = symbol.entry["st_shndx"]
                if (
                    symbol.name.startswith(".L.str")
                    and shndx in target_sections
                    and symbol.entry["st_info"]["bind"] == "STB_LOCAL"
                ):
                    new_symbol_name = symbol.name.replace(".L.", symbol_base_name)
                    objcopy_args.append("--add-symbol")
                    objcopy_args.append(
                        f"{new_symbol_name}={target_sections[shndx].name}:{hex(symbol.entry['st_value'])},global",
                    )

    p = await asyncio.create_subprocess_exec(
        "objcopy",
        filepath,
        *objcopy_args,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(p.communicate(), timeout=60)
    except asyncio.TimeoutError:
        p.kill()
        raise
    if p.returncode != 0:
        raise RuntimeError("objcopy error: " + stderr.decode())


async def add_float_symbols(filepath: str | Path):
    symbol_base_name = (
        "decgcpi_" + os.path.basename(str(filepath)).removesuffix(".o") + "_"
    )
    with open(filepath, "rb") as f:  # noqa: ASYNC230
        elffile = ELFFile(f)
        target_sections = {}
        for section_id in range(elffile.num_sections()):
            section = elffile.get_section(section_id)
            if section.name.startswith(".rodata.cst"):
                target_sections[section_id] = section
        symbol_tables = [
            s for s in elffile.iter_sections() if isinstance(s, SymbolTableSection)
        ]
        objcopy_args = []
        for symtab in symbol_tables:
            for symbol in symtab.iter_symbols():
                shndx = symbol.entry["st_shndx"]
                if (
                    symbol.name.startswith(".LCPI")
                    and shndx in target_sections
                    and symbol.entry["st_info"]["bind"] == "STB_LOCAL"
                ):
                    new_symbol_name = symbol.name.replace(".LCPI", symbol_base_name)
                    objcopy_args.append("--add-symbol")
                    objcopy_args.append(
                        f"{new_symbol_name}={target_sections[shndx].name}:{hex(symbol.entry['st_value'])},global",
                    )

    p = await asyncio.create_subprocess_exec(
        "objcopy",
        filepath,
        *objcopy_args,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(p.communicate(), timeout=60)
    except asyncio.TimeoutError:
        p.kill()
        raise
    if p.returncode != 0:
        raise RuntimeError("objcopy error: " + stderr.decode())
