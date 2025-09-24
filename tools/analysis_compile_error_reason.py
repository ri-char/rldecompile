import asyncio
import json
import os
import re
import tempfile
from typing import Optional

import httpx
from aiofiles import open
from loguru import logger

from eval import find_ans
from lib.exe_bench_problem import ExeBenchProblem
from lib.llm_api import CallLLMError, call_llm, local_api_client
from lib.utils import PROJECT_ROOT, client, get_progress_bar, init_jinja_env, init_log

httpx_clent = httpx.AsyncClient()

env = init_jinja_env()


class Entry:
    problem_id: str
    model: str
    optLevel: str
    ans: str


CLANG_ERROR_FORMAT = re.compile(
    r"^.*?:[0-9]+:[0-9]+: (?:fatal )?error: (.*)$", re.MULTILINE
)


async def compile_check_error(
    problem: ExeBenchProblem, extra_code: Optional[str]
) -> list[str]:
    source_code = str(tempfile.mktemp(prefix="compile_check_", suffix=".cpp"))
    other_header = "#include <stdint.h>\n#include <stdlib.h>\n#include <unistd.h>\n"
    full_code = re.compile(
        r"^\s*#include\s+[<\"]" + re.escape(problem.required_includes) + r"[>\"]\s*$",  # type: ignore
        re.MULTILINE,
    ).sub(
        lambda _: (
            other_header
            + problem.deps
            + "\n"
            + (extra_code + "\n" if extra_code is not None else "")
            + problem.func_def
        ),
        problem.exe_wrapper,
    )
    async with open(source_code, "w") as f:
        await f.write(full_code)

    general_args = [
        "-gdwarf-4",
        "-Wno-implicit-int",
        "-I" + os.path.join(PROJECT_ROOT, "exebench", "exebench"),
        "-S",
    ]

    p = await asyncio.create_subprocess_exec(
        "clang++",
        source_code,
        "-o",
        "/dev/null",
        *general_args,
        stderr=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, stderr = await asyncio.wait_for(p.communicate(), timeout=30)
        if p.returncode != 0:
            return CLANG_ERROR_FORMAT.findall(stderr.decode())

    except (asyncio.exceptions.CancelledError, asyncio.TimeoutError):
        try:
            p.kill()
        except ProcessLookupError:
            pass
        raise
    return []


async def eval_problem(
    problem: ExeBenchProblem,
    optLevel: str,
    model_name: str,
    collection_name: str = "functions",
    template_name="prompt.jinja",
):
    if problem.io_pairs is None:
        return
    problem_id = problem.id
    decompiled_code: dict[str, str] = {}
    logger.debug(
        f"find in mongodb where binary is {problem_id} and optLevel is {optLevel}"
    )
    async for function in client[collection_name].find(
        {"binary": problem_id, "optLevel": optLevel}
    ):
        logger.debug(
            f"Processing function: {function['name']} for problem: {problem_id}"
        )
        prompt = env.get_template(template_name).render(**function)
        logger.debug("Call LLM " + model_name)
        ans = await call_llm(prompt, model_name)
        if isinstance(ans, CallLLMError):
            return

        ans = find_ans(ans)
        if ans is None:
            logger.debug(
                f"No c code in answer for function: {function['name']}, problem: {problem_id}"
            )
            return
        decompiled_code[function["name"]] = ans
    new_problem = problem.model_copy()
    new_problem.func_def = "\n".join(decompiled_code.values())
    logger.debug(f"Attempting to compile and run tests for problem: {problem_id}")
    io_pairs = json.loads(new_problem.io_pairs)  # type: ignore

    extra_codes: list[Optional[str]] = []
    for test in io_pairs:
        if test["dummy_funcs"] not in extra_codes:
            extra_codes.append(test["dummy_funcs"])
    errors = []
    for ec in extra_codes:
        errors = await compile_check_error(new_problem, ec)
        if len(errors) != 0:
            break
    if len(errors) != 0:
        await client["compile_error_type"].insert_one(
            {
                "problem": problem_id,
                "optLevel": optLevel,
                "error": errors,
                "model": model_name,
            }
        )


async def eval_all_exebench_problems(
    optLevel: str, model_name: str, total_times: int = 5
):
    total = await client["exebench"].count_documents({"label": "real_test"})
    p = get_progress_bar(console)
    p.start()
    task = p.add_task(optLevel, total=total)

    worker_number = len(local_api_client) * 2
    queue: asyncio.Queue = asyncio.Queue(worker_number)

    async def worker():
        while True:
            row = await queue.get()
            try:
                for _ in range(total_times):
                    try:
                        problem = ExeBenchProblem.model_validate(row)
                        collection = "functions"
                        template_file = "prompt.jinja"
                        await eval_problem(
                            problem, optLevel, model_name, collection, template_file
                        )
                    except Exception:
                        logger.exception(f"eval {row['id']} failed")
            finally:
                queue.task_done()
                p.update(task, advance=1)

    workers = [asyncio.create_task(worker()) for _ in range(worker_number)]
    await client["compile_error_type"].delete_many(
        {"optLevel": optLevel, "model": model_name}
    )
    session = client.client.start_session()
    async for row in client["exebench"].find(
        {"label": "real_test"},
        projection={"_id": False},
        session=session,
        no_cursor_timeout=True,
    ):
        await queue.put(row)
        await client.command("refreshSessions", [session.session_id])
    await session.end_session()
    await queue.join()

    p.stop()
    for w in workers:
        w.cancel()


async def main():
    models = [("rldeompile-1.3b", False)]

    for model, need_load_lora in models:
        logger.info("start to evaluation model " + model)
        if need_load_lora:
            logger.info("load model " + model)
            await local_api_client.load_lora_module(model)
        for optLevel in ["O0", "O1", "O2", "O3", "Os"]:
            logger.info(f"eval model {model} for {optLevel}")
            await eval_all_exebench_problems(optLevel, model)
        if need_load_lora:
            logger.info("unload model " + model)
            await local_api_client.unload_lora_module(model)


console = init_log("INFO")
asyncio.run(main())
