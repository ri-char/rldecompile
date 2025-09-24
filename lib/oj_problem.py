import asyncio
import os
import shlex
import tempfile
import xml.etree.ElementTree
from typing import Optional

from aiofiles import open
from bson import ObjectId
from loguru import logger
from pydantic import BaseModel
from pymongo.asynchronous.collection import AsyncCollection

from lib.code_analysis import (
    normalize_code,
    remove_intervals,
)
from lib.elf_analysis import add_float_symbols, add_string_symbols
from lib.utils import (
    PROJECT_ROOT,
    ClangFunctionInfo,
    ResourceDir,
    client,
    get_progress_bar,
    get_xclang_args,
    init_log,
    run_with_log,
)


class TestCase(BaseModel):
    test_input: str
    test_output: str


class OjProblem(BaseModel):
    id: str
    code: str
    header_code: Optional[str]
    tests: list[TestCase]

    @staticmethod
    def parse_xml(p: str) -> list["OjProblem"]:
        xml_tree = xml.etree.ElementTree.parse(p)
        result: list["OjProblem"] = []
        filename = os.path.basename(p).rsplit(".", 1)[0]
        for i, prob in enumerate(xml_tree.getroot().findall("item")):
            solution = prob.find("solution[@language='C']")
            if solution is None:
                continue
            code = solution.text
            test_input = prob.findtext("test_input")
            test_output = prob.findtext("test_output")
            if code is None or test_input is None or test_output is None:
                continue
            result.append(
                OjProblem(
                    id=f"{filename}.{i}",
                    code=code,
                    tests=[TestCase(test_input=test_input, test_output=test_output)],
                    header_code=None,
                )
            )
        return result

    async def _compile_for_test(self, compile_flags: list[str] = []) -> ResourceDir:
        logger.debug(f"create temp dir for {self.id}")
        output = ResourceDir(tempfile.mkdtemp(prefix="decompile_tmp_"))
        source_code = str(output.source_code())
        logger.debug("compile " + source_code)
        async with open(source_code, "w") as f:
            await f.write(self.code)

        general_args = [
            "-gdwarf-4",
            "-Wno-implicit-int",
        ] + compile_flags

        await run_with_log(
            ["clang", source_code, "-o", str(output.executable_binary())]
            + general_args,
            "compile",
        )
        logger.debug("compile " + source_code + " done")
        return output

    async def compile_with_info(self, compile_flags: list[str] = []) -> ResourceDir:
        logger.debug(f"create temp dir for {self.id}")
        output = ResourceDir(tempfile.mkdtemp(prefix="decompile_tmp_"))
        source_code = str(output.source_code())
        logger.debug("compile " + source_code)
        async with open(source_code, "w") as f:
            await f.write(self.code)

        general_args = [
            "-gdwarf-4",
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
        logger.debug("add global string symbol")
        await add_string_symbols(output.object_binary())
        await add_float_symbols(output.object_binary())

        await run_with_log(
            [
                "clang",
                str(output.object_binary()),
                "-o",
                str(output.executable_binary()),
            ]
            + general_args,
            "final compile",
        )
        logger.debug("compile " + source_code + " done")
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
            str(compile_output_path.executable_binary()),
            "-deleteProject",
            "-postScript",
            "Main.java",
            ghidra_arg,
            "-scriptPath",
            os.path.join(PROJECT_ROOT, "ghidra_exporter", "src", "main", "java"),
        ]
        logger.debug("ghidra command: " + shlex.join(cmdline))
        p = await asyncio.create_subprocess_exec(
            *cmdline, stderr=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(p.communicate(), timeout=20 * 60)
            if stderr.count(b"\n") > 10:
                logger.debug("ghidra stdout: " + stdout.decode())
                logger.warning("ghidra stderr: " + stderr.decode())
            if p.returncode != 0:
                raise RuntimeError(stdout.decode())
        except asyncio.TimeoutError:
            p.kill()
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

        intervals = []
        for clang_function_info in clang_function_infos:
            intervals.append(
                (clang_function_info.begin_offset, clang_function_info.end_offset)
            )
        header_code = remove_intervals(self.code.encode(), intervals)
        header_code = await normalize_code(header_code)
        self.header_code = header_code

    async def run_tests(self, compile_flags: list[str] = []) -> tuple[bool, bool]:
        try:
            compile_output_path = await self._compile_for_test(
                compile_flags=compile_flags
            )
            for test in self.tests:
                p = await asyncio.create_subprocess_exec(
                    str(compile_output_path.executable_binary()),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                try:
                    if p.stdin is not None:
                        p.stdin.write(test.test_input.encode())
                        p.stdin.close()
                    stdout, stderr = await asyncio.wait_for(
                        p.communicate(), timeout=120
                    )
                except asyncio.TimeoutError:
                    logger.debug("run test timeout")
                    p.kill()
                    return True, False
                if p.returncode != 0:
                    logger.debug(
                        f"run test failed because return code is {p.returncode}"
                    )
                    return True, False
                if stdout.decode().strip("\n") != test.test_output.strip("\n"):
                    logger.debug(
                        f"run test failed because output {p.stdout} != {test.test_output.encode()}"
                    )
                    return True, False
        except (RuntimeError, asyncio.TimeoutError, asyncio.exceptions.CancelledError):
            return False, False
        finally:
            if "compile_output_path" in locals():
                compile_output_path.delete()  # type: ignore

        return True, True


async def load_oj_xml(xml_path: str) -> list[OjProblem]:
    try:
        problem_list = OjProblem.parse_xml(xml_path)
    except xml.etree.ElementTree.ParseError:
        logger.warning(f"load {xml_path} failed")
        return []
    func_collection = client["functions"]
    oj_problem_collection = client["oj_problems"]
    await oj_problem_collection.create_index("id", unique=True)

    for problem in problem_list:
        await oj_problem_collection.delete_one({"id": problem.id})
        await func_collection.delete_many({"binary": problem.id})
        for optLevel in ["O0", "O1", "O2", "O3", "Os"]:
            try:
                await oj_problem_collection.insert_one(
                    problem.model_dump() | {"_id": ObjectId()}
                )
                if not await problem.run_tests(["-" + optLevel]):
                    continue
                binary_path = await problem.compile_with_info(["-" + optLevel])
                await problem.ghidra_analysis(func_collection, binary_path, optLevel)
            except (asyncio.TimeoutError, RuntimeError):
                logger.warning(f"load {problem.id}({optLevel}) failed, deleting it.")
                await func_collection.delete_many(
                    {"binary": problem.id, "optLevel": optLevel}
                )
                if await func_collection.count_documents({"binary": problem.id}) == 0:
                    await oj_problem_collection.delete_one({"id": problem.id})
            finally:
                if "binary_path" in locals() and binary_path.base_dir.exists():  # type: ignore
                    logger.debug(f"delete temp dir {problem.id}")
                    binary_path.delete()  # type: ignore
    return problem_list


async def __main():
    console = init_log("INFO")
    files = os.listdir(os.path.join(PROJECT_ROOT, "dataset", "oj_dataset"))
    p = get_progress_bar(console)
    p.start()
    task = p.add_task("load_oj_xml", total=len(files))
    for xml_file in files:
        await load_oj_xml(os.path.join(PROJECT_ROOT, "dataset", "oj_dataset", xml_file))
        p.update(task, advance=1)
    # await load_oj_xml(os.path.join(PROJECT_ROOT, "dataset", "oj_dataset", "1006.xml"))


if __name__ == "__main__":
    asyncio.run(__main())
