import asyncio
import os
import re

from loguru import logger

from lib.exe_bench_problem import ExeBenchProblem
from lib.utils import (
    client,
    get_progress_bar,
    init_log,
)

zeros_pattern = re.compile(r"^0+\s|\_\_attribute\_\_\(\(used\)\) ")  # 0000000000000...
asm_patten = re.compile(
    r"^.*\t(.*?)\s*(#.*)?$", re.MULTILINE
)  # remove the binary code and comments


def clean_asm(asm: str) -> str:
    asm = asm.split("Disassembly of section .text:")[-1].strip()
    asm = asm_patten.sub(r"\1", asm)
    ##### end of clean up

    ##### start of filter digits and attribute
    asm = zeros_pattern.sub("", asm)
    ##### end of filter digits

    return asm


async def __main():
    console = init_log("INFO")

    total = await client["exebench"].count_documents({"label": "real_test"})
    p = get_progress_bar(console)
    task = p.add_task("eval", total=total)
    p.start()

    llm4decompile_collection = client["llm4decompile_function"]

    worker_number = os.cpu_count() or 8
    queue: asyncio.Queue = asyncio.Queue(worker_number)

    async def worker():
        while True:
            row = await queue.get()
            try:
                problem = ExeBenchProblem.model_validate(row)
                for optLevel in ["O0", "O1", "O2", "O3", "Os"]:
                    compile_result = await problem.compile(["-" + optLevel])
                    logger.debug("objdump " + problem.id + " " + optLevel)
                    proc = await asyncio.create_subprocess_exec(
                        "objdump",
                        "-d",
                        str(compile_result.object_binary()),
                        stderr=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stdin=asyncio.subprocess.DEVNULL,
                    )
                    try:
                        stdout, stderr = await asyncio.wait_for(
                            proc.communicate(), timeout=30
                        )
                        if proc.returncode != 0:
                            logger.debug(problem.id + " " + optLevel + " objdump fails")
                            raise RuntimeError(stderr.decode())
                        logger.debug(
                            problem.id
                            + " "
                            + optLevel
                            + " objdump success, start to clean asm"
                        )
                        asm = clean_asm(stdout.decode())
                        logger.debug(
                            problem.id
                            + " "
                            + optLevel
                            + " clean asm success, insert to db"
                        )
                        await llm4decompile_collection.update_one(
                            {
                                "_id": problem.id + "-" + optLevel,
                            },
                            {
                                "$set": {
                                    "name": problem.id,
                                    "binary": problem.id,
                                    "optLevel": optLevel,
                                    "asm": asm,
                                }
                            },
                            upsert=True,
                        )
                        logger.debug(
                            problem.id + " " + optLevel + " insert to db success"
                        )
                    except (
                        asyncio.exceptions.CancelledError,
                        asyncio.TimeoutError,
                    ) as e:
                        logger.error(
                            "command error or timeout in "
                            + problem.id
                            + " "
                            + optLevel
                            + " "
                            + str(e)
                        )
                        try:
                            proc.kill()
                        except ProcessLookupError:
                            pass
                    except RuntimeError as e:
                        logger.error(
                            "objdump command error in "
                            + problem.id
                            + " "
                            + optLevel
                            + " stderr: "
                            + e.args[0]
                        )
                    except Exception as e:
                        logger.exception(
                            "unexpected error in "
                            + problem.id
                            + " "
                            + optLevel
                            + " msg: "
                            + str(e)
                        )
            finally:
                queue.task_done()
                p.update(task, advance=1)

    workers = [asyncio.create_task(worker()) for _ in range(worker_number)]
    async for row in client["exebench"].find(
        {"label": "real_test"},
        projection={"_id": False},
    ):
        await queue.put(row)

    await queue.join()

    p.stop()
    for w in workers:
        w.cancel()


if __name__ == "__main__":
    asyncio.run(__main())
