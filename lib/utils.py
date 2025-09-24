import asyncio
import math
import os
import shlex
import shutil
from pathlib import Path
from typing import Iterable, Union

from aiofiles import open
from jinja2 import Environment, FileSystemLoader, select_autoescape
from loguru import logger
from pydantic import BaseModel
from pymongo import AsyncMongoClient
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.text import Text

client = AsyncMongoClient(os.environ["MONGODB"])["decompile"]

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
)


class ClangFunctionInfo(BaseModel):
    name: str
    filename: str
    begin_offset: int
    end_offset: int

    @staticmethod
    async def load_jsonl(p: Path) -> list["ClangFunctionInfo"]:
        result = []
        async with open(p, "r") as f:
            async for jsonl in f:
                if len(jsonl.strip()) == 0:
                    continue
                result.append(ClangFunctionInfo.model_validate_json(jsonl))
        return result


class ResourceDir:
    base_dir: Path
    cpp_mode: bool

    def __init__(self, base_dir: Union[str, Path], cpp_mode: bool = False) -> None:
        if isinstance(base_dir, Path):
            self.base_dir = base_dir
        else:
            self.base_dir = Path(base_dir)
        self.cpp_mode = cpp_mode

    def source_code(self) -> Path:
        if self.cpp_mode:
            return self.base_dir / "src.cpp"
        else:
            return self.base_dir / "src.c"

    def macro_expanded_code(self) -> Path:
        return self.base_dir / "macro_expanded_src.c"

    def clang_function_info(self) -> Path:
        return self.base_dir / "dump.jsonl"

    def macro_expand_clang_function_info(self) -> Path:
        return self.base_dir / "macro_expanded_dump.jsonl"

    def object_binary(self) -> Path:
        return self.base_dir / "a.o"

    def executable_binary(self) -> Path:
        return self.base_dir / "a.out"

    def ghidra_project(self) -> Path:
        return self.base_dir / "ghidra_project"

    def __str__(self) -> str:
        return str(self.base_dir)

    def delete(self):
        shutil.rmtree(self.base_dir)

    def __del__(self):
        if os.path.exists(self.base_dir):
            self.delete()


def init_jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(os.path.join(PROJECT_ROOT, "prompts")),
        autoescape=select_autoescape(),
    )


def init_log(level: str = "INFO") -> Console:
    console = Console(stderr=True)
    logger.configure(
        handlers=[
            {
                "sink": lambda s: console.print(Text.from_ansi(s)),
                "colorize": console.is_terminal,
                "level": level,
            }
        ]
    )
    return console


async def run_with_log(cmdline: list[str], log_id: str = ""):
    logger.debug(log_id + " compile command: " + shlex.join(cmdline))
    p = await asyncio.create_subprocess_exec(
        *cmdline,
        stderr=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, stderr = await asyncio.wait_for(p.communicate(), timeout=30)
        if p.returncode != 0:
            raise RuntimeError(stderr.decode())
    except (asyncio.exceptions.CancelledError, asyncio.TimeoutError):
        logger.error(log_id + " command error")
        try:
            p.kill()
        except ProcessLookupError:
            pass
        raise


def get_xclang_args(path: str | Path) -> list[str]:
    xclang_args = [
        "-load",
        os.path.join(
            PROJECT_ROOT,
            "clang-function-range-plugin",
            "build",
            "libFunctionRange.so",
        ),
        "-plugin",
        "FunctionRange",
        "-plugin-arg-FunctionRange",
        str(path),
    ]
    for i in range(len(xclang_args)):
        xclang_args.insert(i * 2, "-Xclang")
    return xclang_args


def diff_io(observed_output, expected_output) -> bool:
    if type(observed_output) is not type(expected_output):
        return False
    if isinstance(observed_output, list):
        if len(observed_output) != len(expected_output):
            return False
        for e1, e2 in zip(observed_output, expected_output):
            ok = diff_io(e1, e2)
            if not ok:
                return False
    elif isinstance(observed_output, dict):
        for key in observed_output:
            if key not in expected_output:
                return False
            ok = diff_io(observed_output[key], expected_output[key])
            if not ok:
                return False
    elif isinstance(observed_output, float):
        ok = math.isclose(observed_output, expected_output)
        if not ok:
            return False
    else:
        ok = observed_output == expected_output
        if not ok:
            return False
    return True


def get_progress_bar(console: Console | None = None, **kargs) -> Progress:
    return Progress(
        TextColumn("[progress.description]{task.description}"),
        TextColumn("•"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        TextColumn("•"),
        TimeRemainingColumn(),
        console=console,
        expand=True,
        **kargs,
    )


def wrong_count_to_passk(
    wrong_count: list[int], total_times: int, k: Iterable[int] | None = None
) -> list[float]:
    if k is None:
        k = range(1, total_times + 1)
    passk = []
    if len(wrong_count) == 0:
        for _ in k:
            passk.append(math.nan)
    else:
        for i in k:
            total_choices = math.comb(total_times, i)
            passk.append(
                sum(
                    map(
                        lambda wrong: 1 - math.comb(wrong, i) / total_choices,
                        wrong_count,
                    )
                )
                / len(wrong_count)
            )
    return passk
