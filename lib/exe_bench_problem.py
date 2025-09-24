import asyncio
import json
import os
import re
import shlex
import sys
import tempfile
from typing import Optional

from aiofiles import open
from bson import ObjectId
from loguru import logger
from opentelemetry.trace import Tracer
from opentelemetry.trace.status import StatusCode
from pydantic import BaseModel
from pymongo.asynchronous.collection import AsyncCollection
from rich.console import Console

from lib.code_analysis import (
    is_empty_function,
    normalize_code,
)
from lib.elf_analysis import add_float_symbols, add_string_symbols
from lib.utils import (
    PROJECT_ROOT,
    ClangFunctionInfo,
    ResourceDir,
    client,
    diff_io,
    get_progress_bar,
    get_xclang_args,
    init_log,
    run_with_log,
)


class ExeBenchProblem(BaseModel):
    id: str
    func_name: str
    func_def: str
    deps: str
    label: Optional[str]

    have_test: bool
    io_pairs: Optional[str]
    exe_wrapper: Optional[str]
    required_includes: Optional[str]

    @staticmethod
    def parse_json(p: str, id: str, label: Optional[str]) -> "ExeBenchProblem":
        data = json.loads(p)["text"]
        base = "real"
        if data["real_exe_wrapper"] is None:
            base = "angha"
        have_test = data[base + "_iospec"] is not None
        return ExeBenchProblem(
            id=id,
            func_name=data["fname"],
            func_def=data["func_def"],
            deps=data[base + "_deps"] or data["real_deps"],
            label=label,
            have_test=have_test,
            io_pairs=json.dumps(data[base + "_io_pairs"], ensure_ascii=False)
            if have_test
            else None,
            exe_wrapper=data[base + "_exe_wrapper"] if have_test else None,
            required_includes=data[base + "_iospec"]["required_includes"][0]
            if have_test
            else None,
        )

    async def _compile_for_test(
        self, extra_code: Optional[str], compile_flags: list[str] = []
    ) -> ResourceDir:
        logger.debug(f"create temp dir for {self.id}")
        output = ResourceDir(tempfile.mkdtemp(prefix="decompile_tmp_"), cpp_mode=True)
        source_code = str(output.source_code())
        logger.debug("compile " + source_code)
        other_header = "#include <stdint.h>\n#include <stdlib.h>\n#include <unistd.h>\n"
        full_code = re.compile(
            r"^\s*#include\s+[<\"]" + re.escape(self.required_includes) + r"[>\"]\s*$",  # type: ignore
            re.MULTILINE,
        ).sub(
            lambda _: (
                other_header
                + self.deps
                + "\n"
                + (extra_code + "\n" if extra_code is not None else "")
                + self.func_def
            ),
            self.exe_wrapper,
        )
        async with open(source_code, "w") as f:
            await f.write(full_code)

        general_args = [
            "-gdwarf-4",
            "-Wno-implicit-int",
            "-I" + os.path.join(PROJECT_ROOT, "exebench", "exebench"),
            "-L" + os.path.join(PROJECT_ROOT, "exebench", "exebench", "clib"),
            "-lclib",
        ] + compile_flags

        try:
            await run_with_log(
                ["clang++", source_code, "-o", str(output.executable_binary())]
                + general_args,
                "compile",
            )
        except (asyncio.exceptions.CancelledError, asyncio.TimeoutError):
            output.delete()
            raise
        logger.debug("compile " + self.id + " done")
        return output

    async def compile(self, compile_flags: list[str] = []) -> ResourceDir:
        logger.debug(f"create temp dir for {self.id}")
        output = ResourceDir(tempfile.mkdtemp(prefix="decompile_tmp_"))

        source_code = str(output.source_code())
        logger.debug("compile " + source_code)
        async with open(source_code, "w") as f:
            await f.write(self.deps.replace("# 1", ""))
            await f.write("\n")
            await f.write(self.func_def)
        general_args = [
            "-Wno-implicit-int",
        ] + compile_flags

        await run_with_log(
            [
                "clang",
                source_code,
                "-c",
                "-o",
                str(output.object_binary()),
            ]
            + general_args,
            "compile .o",
        )
        logger.debug("compile " + self.id + " done")
        return output

    async def compile_with_info(self, compile_flags: list[str] = []) -> ResourceDir:
        logger.debug(f"create temp dir for {self.id}")
        output = ResourceDir(tempfile.mkdtemp(prefix="decompile_tmp_"))

        source_code = str(output.source_code())
        logger.debug("compile " + source_code)
        async with open(source_code, "w") as f:
            await f.write(self.deps.replace("# 1", ""))
            await f.write("\n")
            await f.write(self.func_def)
        general_args = [
            "-Wno-implicit-int",
        ] + compile_flags

        await run_with_log(
            [
                "clang",
                source_code,
                "-E",
                "-o",
                "/dev/null",
            ]
            + get_xclang_args(output.clang_function_info())
            + general_args,
            "function range",
        )
        await run_with_log(
            [
                "clang",
                source_code,
                "-E",
                "-o",
                str(output.macro_expanded_code()),
            ]
            + general_args,
            "macro expand",
        )

        await run_with_log(
            ["clang", str(output.macro_expanded_code()), "-E", "-o", "/dev/null"]
            + get_xclang_args(output.macro_expand_clang_function_info())
            + general_args,
            "function range with macro expanded",
        )

        await run_with_log(
            [
                "clang",
                source_code,
                "-c",
                "-o",
                str(output.object_binary()),
            ]
            + general_args,
            "compile .o",
        )
        logger.debug("add global string symbol for " + self.id)
        await add_string_symbols(output.object_binary())
        await add_float_symbols(output.object_binary())
        logger.debug("compile " + self.id + " done")
        return output

    async def ghidra_analysis(
        self,
        func_collection: AsyncCollection,
        compile_output_path: ResourceDir,
        optLevel: str,
    ):
        ghidra_name = "ghidra_project"
        if not os.path.exists(
            compile_output_path.clang_function_info()
        ) or not os.path.exists(compile_output_path.macro_expand_clang_function_info()):
            logger.warning(
                f"connot found clang_function_info or macro_expand_clang_function_info for problem {self.id}"
            )
            return
        os.mkdir(compile_output_path.ghidra_project())
        clang_function_infos = await ClangFunctionInfo.load_jsonl(
            compile_output_path.clang_function_info()
        )
        macro_expanded_infos = await ClangFunctionInfo.load_jsonl(
            compile_output_path.macro_expand_clang_function_info()
        )
        ghidra_arg = ",|||,".join(
            [self.id, optLevel] + list(map(lambda x: x.name, clang_function_infos))
        )
        logger.debug(f"ghidra analysis {self.id} start")
        cmdline = [
            "ghidra-analyzeHeadless",
            str(compile_output_path.ghidra_project()),
            ghidra_name,
            "-import",
            str(compile_output_path.object_binary()),
            "-deleteProject",
            "-postScript",
            "Main.java",
            ghidra_arg,
            "-scriptPath",
            os.path.join(PROJECT_ROOT, "ghidra_exporter", "src", "main", "java"),
        ]
        logger.debug("ghidra command: " + shlex.join(cmdline))

        p = await asyncio.create_subprocess_exec(
            *cmdline,
            stderr=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, stderr = await asyncio.wait_for(p.communicate(), timeout=20 * 60)
            if stderr.count(b"\n") > 10:
                logger.debug("ghidra stdout: " + stdout.decode())
                logger.warning("ghidra stderr: " + stderr.decode())
            if p.returncode != 0:
                raise RuntimeError(stdout.decode())
        except (asyncio.exceptions.CancelledError, asyncio.TimeoutError):
            try:
                p.kill()
            except ProcessLookupError:
                pass
            raise

        logger.debug(f"ghidra analysis {self.id} done")

        logger.debug(f"start insert extra information for {self.id}")

        async for row in func_collection.find(
            {"binary": self.id, "optLevel": optLevel}
        ):
            for clang_function_info in clang_function_infos:
                if row["name"] == clang_function_info.name:
                    break
            else:
                logger.debug("delete function " + row["name"] + " from " + self.id)
                await func_collection.delete_one({"_id": row["_id"]})
                continue
            for expanded_info in macro_expanded_infos:
                if row["name"] == expanded_info.name:
                    break
            else:
                logger.debug("delete function " + row["name"] + " from " + self.id)
                await func_collection.delete_one({"_id": row["_id"]})
                continue

            async with open(compile_output_path.macro_expanded_code(), "rb") as f:
                await f.seek(expanded_info.begin_offset)
                code = await f.read(
                    expanded_info.end_offset - expanded_info.begin_offset + 1
                )
            code = await normalize_code(code)
            decompiled_code = await normalize_code(row["decompiled_code"])
            logger.debug(f"fix function {row['name']} in {self.id}")
            await func_collection.update_one(
                {"_id": row["_id"]},
                {"$set": {"source_code": code, "decompiled_code": decompiled_code}},
            )
        logger.debug(f"insert extra information for {self.id} done")

    async def run_tests(self, compile_flags: list[str] = []) -> tuple[bool, bool]:
        if (
            not self.have_test
            or self.io_pairs is None
            or self.exe_wrapper is None
            or self.required_includes is None
        ):
            return True, True

        async def compile_worker(extra_code: Optional[str]) -> Optional[ResourceDir]:
            try:
                return await self._compile_for_test(
                    extra_code, compile_flags=compile_flags
                )
            except (
                RuntimeError,
                asyncio.TimeoutError,
                asyncio.exceptions.CancelledError,
            ):
                return None

        async def run_test_worker(test, resource_dir: Optional[ResourceDir]) -> bool:
            if resource_dir is None:
                return False
            try:
                input_file_fd, input_file = tempfile.mkstemp(
                    prefix="decompile_input_file"
                )
                output_file_fd, output_file = tempfile.mkstemp(
                    prefix="decompile_output_file"
                )
                os.close(input_file_fd)
                os.close(output_file_fd)
                async with open(input_file, "w") as f:
                    dump = json.dumps(test["input"])
                    await f.write(dump)

                p = await asyncio.create_subprocess_exec(
                    str(resource_dir.executable_binary()),
                    input_file,
                    output_file,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    cwd=str(resource_dir.base_dir),
                )
                await asyncio.wait_for(p.wait(), timeout=3)
                if p.returncode != 0:
                    logger.debug(
                        f"run test failed because return code is {p.returncode}"
                    )
                    return False
                async with open(output_file, "r") as f:
                    content = await f.read()
                    output = json.loads(content)
                if not diff_io(output, test["output"]):
                    logger.debug(
                        f"run test failed because observed output: {output} != expected output: {test['output']}"
                    )
                    return False
                return True
            except (asyncio.exceptions.CancelledError, asyncio.TimeoutError):
                logger.debug("run test timeout")
                if "p" in locals():
                    try:
                        p.kill()  # type: ignore
                    except ProcessLookupError:
                        pass
                return False
            except json.JSONDecodeError:
                logger.debug("run test failed because output is not valid json")
                return False
            finally:
                if "input_file" in locals() and os.path.exists(input_file):  # type: ignore
                    os.remove(input_file)  # type: ignore
                if "output_file" in locals() and os.path.exists(output_file):  # type: ignore
                    os.remove(output_file)  # type: ignore

        io_pairs = json.loads(self.io_pairs)

        # list all binary that need to compile
        extra_codes: list[Optional[str]] = []
        for test in io_pairs:
            if test["dummy_funcs"] not in extra_codes:
                extra_codes.append(test["dummy_funcs"])

        resource_dir_list: list[Optional[ResourceDir]] = await asyncio.gather(
            *[compile_worker(code) for code in extra_codes]
        )
        if any(v is None for v in resource_dir_list):
            for resource_dir in resource_dir_list:
                if resource_dir is not None:
                    resource_dir.delete()
            return False, False
        resource_dir_dict: dict[Optional[str], Optional[ResourceDir]] = {
            k: v for k, v in zip(extra_codes, resource_dir_list)
        }

        total_tests = len(io_pairs)
        passed_tests = 0
        result = await asyncio.gather(
            *[
                run_test_worker(test, resource_dir_dict[test["dummy_funcs"]])
                for test in io_pairs
                if resource_dir_dict[test["dummy_funcs"]] is not None
            ]
        )

        for res in result:
            if res:
                passed_tests += 1

        for resource_dir in resource_dir_list:
            if resource_dir is not None:
                resource_dir.delete()
        return True, total_tests == passed_tests

    async def run_tests_reward(
        self, tracer: Tracer, compile_flags: list[str] = []
    ) -> tuple[float, float]:
        if (
            not self.have_test
            or self.io_pairs is None
            or self.exe_wrapper is None
            or self.required_includes is None
        ):
            return 0.0, 0.0

        async def compile_worker(extra_code: Optional[str]) -> Optional[ResourceDir]:
            with tracer.start_as_current_span("compile") as compile_span:
                try:
                    return await self._compile_for_test(
                        extra_code, compile_flags=compile_flags
                    )
                except (
                    RuntimeError,
                    asyncio.TimeoutError,
                    asyncio.exceptions.CancelledError,
                ):
                    compile_span.set_status(StatusCode.ERROR)
                    return None

        async def run_test_worker(
            test, resource_dir: Optional[ResourceDir]
        ) -> tuple[int, int]:
            if resource_dir is None:
                return 0, 0
            with tracer.start_as_current_span("run_test") as run_span:
                try:
                    input_file_fd, input_file = tempfile.mkstemp(
                        prefix="decompile_input_file"
                    )
                    output_file_fd, output_file = tempfile.mkstemp(
                        prefix="decompile_output_file"
                    )
                    os.close(input_file_fd)
                    os.close(output_file_fd)
                    async with open(input_file, "w") as f:
                        dump = json.dumps(test["input"])
                        await f.write(dump)

                    p = await asyncio.create_subprocess_exec(
                        str(resource_dir.executable_binary()),
                        input_file,
                        output_file,
                        stdin=asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                        cwd=str(resource_dir.base_dir),
                    )
                    await asyncio.wait_for(p.wait(), timeout=3)
                    if p.returncode != 0:
                        logger.debug(
                            f"run test failed because return code is {p.returncode}"
                        )
                        run_span.set_attribute("error", "run test failed")
                        return 1, 0
                    async with open(output_file, "r") as f:
                        content = await f.read()
                        output = json.loads(content)
                    if not diff_io(output, test["output"]):
                        logger.debug(
                            f"run test failed because observed output: {output} != expected output: {test['output']}"
                        )
                        run_span.set_attribute("error", "wrong answer")
                        return 1, 0
                    return 1, 1
                except (asyncio.exceptions.CancelledError, asyncio.TimeoutError):
                    logger.debug("run test timeout")
                    if "p" in locals():
                        try:
                            p.kill()  # type: ignore
                        except ProcessLookupError:
                            pass
                    run_span.set_attribute("error", "timeout")
                    return 1, 0
                except json.JSONDecodeError:
                    logger.debug("run test failed because output is not valid json")
                    run_span.set_status(StatusCode.ERROR)
                    run_span.set_attribute("error", "invalid json")
                    return 1, 0
                finally:
                    if "input_file" in locals() and os.path.exists(input_file):  # type: ignore
                        os.remove(input_file)  # type: ignore
                    if "output_file" in locals() and os.path.exists(output_file):  # type: ignore
                        os.remove(output_file)  # type: ignore

        io_pairs = json.loads(self.io_pairs)

        # list all binary that need to compile
        extra_codes: list[Optional[str]] = []
        for test in io_pairs:
            if test["dummy_funcs"] not in extra_codes:
                extra_codes.append(test["dummy_funcs"])

        resource_dir_list: list[Optional[ResourceDir]] = await asyncio.gather(
            *[compile_worker(code) for code in extra_codes]
        )
        resource_dir_dict: dict[Optional[str], Optional[ResourceDir]] = {
            k: v for k, v in zip(extra_codes, resource_dir_list)
        }

        total_tests = len(io_pairs)
        passed_tests = 0
        compile_passed_tests = 0
        result = await asyncio.gather(
            *[
                run_test_worker(test, resource_dir_dict[test["dummy_funcs"]])
                for test in io_pairs
                if resource_dir_dict[test["dummy_funcs"]] is not None
            ]
        )

        for res in result:
            compile_passed_tests += res[0]
            passed_tests += res[1]

        for resource_dir in resource_dir_list:
            if resource_dir is not None:
                resource_dir.delete()

        if total_tests == 0:
            return 1.0, 1.0
        else:
            return (compile_passed_tests / total_tests, passed_tests / total_tests)


async def load_exe_bench(
    json_path: str,
    base_name: str,
    label: Optional[str],
    console: Console,
    load_empty_function: bool = False,
):
    problem_list: list[ExeBenchProblem] = []
    i = 0
    async with open(json_path, "r") as f:
        async for jsonl in f:
            if len(jsonl.strip()) == 0:
                continue
            i += 1
            problem = ExeBenchProblem.parse_json(jsonl, f"{base_name}-{i}", label)
            problem_list.append(problem)
    func_collection = client["functions"]
    exebench_collection = client["exebench"]
    await exebench_collection.create_index("id", unique=True)
    p = get_progress_bar(console)
    p.start()
    task = p.add_task(f"[yellow]{base_name}", total=len(problem_list))
    queue: asyncio.Queue[ExeBenchProblem] = asyncio.Queue()

    async def worker():
        while True:
            problem = await queue.get()
            try:
                await exebench_collection.delete_one({"id": problem.id})
                await func_collection.delete_many({"binary": problem.id})
                if not load_empty_function and is_empty_function(problem.func_def):
                    logger.warning(f"{problem.id} is empty function, skipping it")
                    continue
                await exebench_collection.insert_one(
                    problem.model_dump() | {"_id": ObjectId()}
                )
                for optLevel in ["O0", "O1", "O2", "O3", "Os"]:
                    try:
                        binary_path = await problem.compile_with_info(["-" + optLevel])
                        await problem.ghidra_analysis(
                            func_collection, binary_path, optLevel
                        )
                    except (
                        RuntimeError,
                        asyncio.TimeoutError,
                        asyncio.exceptions.CancelledError,
                    ):
                        logger.warning(
                            f"load {problem.id}({optLevel}) failed, deleting it."
                        )
                        await func_collection.delete_many(
                            {"binary": problem.id, "optLevel": optLevel}
                        )
                        if (
                            await func_collection.count_documents(
                                {"binary": problem.id}
                            )
                            == 0
                        ):
                            await exebench_collection.delete_one({"id": problem.id})
                    finally:
                        if "binary_path" in locals() and binary_path.base_dir.exists():  # type: ignore
                            logger.debug(f"delete temp dir {problem.id}")
                            binary_path.delete()  # type: ignore
            except BaseException:
                logger.exception(f"load {problem.id} failed")
            finally:
                queue.task_done()
                p.update(task, advance=1)

    workers = [asyncio.create_task(worker()) for _ in range(16)]
    for problem in problem_list:
        await queue.put(problem)
    await queue.join()

    p.stop()
    for w in workers:
        w.cancel()


async def __main():
    label = sys.argv[1] if len(sys.argv) > 1 else "real_test"
    console = init_log("WARNING")
    for file in os.listdir(os.path.join(PROJECT_ROOT, "dataset", label)):
        await load_exe_bench(
            os.path.join(PROJECT_ROOT, "dataset", label, file),
            label + "-" + file.rsplit(".", 1)[0],
            label,
            console,
        )


if __name__ == "__main__":
    asyncio.run(__main())
