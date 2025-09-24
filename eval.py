import asyncio
import os
import re
from enum import Enum

from aiofiles import open
from loguru import logger
from rich import box
from rich.console import Group
from rich.live import Live
from rich.table import Table

from lib.exe_bench_problem import ExeBenchProblem
from lib.llm_api import CallLLMError, call_llm, local_api_client
from lib.oj_problem import OjProblem
from lib.utils import (
    PROJECT_ROOT,
    client,
    get_progress_bar,
    init_jinja_env,
    init_log,
    wrong_count_to_passk,
)

env = init_jinja_env()


def find_ans(ans: str) -> str:
    if ans is None:
        return None
    if ans.startswith("<think>"):
        ans = ans[ans.find("</think>") + len("</think>") :]
    mat = re.finditer(r"```c\n([\s\S]*?)\n```", ans, re.MULTILINE)
    for m in mat:
        return m.group(1)
    mat = re.finditer(r"# What is the source code\?\n([\s\S]*)$", ans, re.MULTILINE)
    for m in mat:
        return m.group(1)
    return ans


class EvalResult(Enum):
    OK = "OK"
    INPUT_LENGTH_EXCEED = "INPUT_LENGTH_EXCEED"
    LENGTH_EXCEED = "LENGTH_EXCEED"
    API_ERROR = "API_ERROR"
    COMPILE_FAIL = "COMPILE_FAIL"
    TEST_FAIL = "TEST_FAIL"

    @staticmethod
    def from_call_llm_error(error: CallLLMError) -> "EvalResult":
        match error:
            case CallLLMError.INPUT_LENGTH_EXCEED:
                return EvalResult.INPUT_LENGTH_EXCEED
            case CallLLMError.LENGTH_EXCEED:
                return EvalResult.LENGTH_EXCEED
            case CallLLMError.API_ERROR:
                return EvalResult.API_ERROR


async def eval_problem(
    problem: OjProblem | ExeBenchProblem,
    optLevel: str,
    model_name: str,
    qid: int | None,
    collection_name: str = "functions",
    template_name="prompt.jinja",
) -> EvalResult:
    problem_id = problem.id
    decompiled_code: dict[str, str] = {}
    logger.debug(f"Starting evaluation for problem: {problem_id}")
    async for function in client[collection_name].find(
        {"binary": problem_id, "optLevel": optLevel}
    ):
        if model_name == "ghidra":
            decompiled_code[function["name"]] = function["decompiled_code"]
        else:
            logger.debug(
                f"Processing function: {function['name']} for problem: {problem_id}"
            )
            prompt = env.get_template(template_name).render(**function)
            ans = await call_llm(prompt, model_name)
            if isinstance(ans, CallLLMError):
                return EvalResult.from_call_llm_error(ans)

            ans = find_ans(ans)
            decompiled_code[function["name"]] = ans
    new_problem = problem.model_copy()
    if isinstance(new_problem, OjProblem):
        full_code_prompt = env.get_template("merge_full_code.jinja").render(
            func_decompiled_code=decompiled_code
        )
        ans = await call_llm(full_code_prompt, model_id="deepseek-chat")
        if isinstance(ans, CallLLMError):
            return EvalResult.from_call_llm_error(ans)
        ans = find_ans(ans)
        logger.debug(f"Received LLM answer for full code merge, problem: {problem_id}")
        new_problem.code = ans
    else:
        new_problem.func_def = "\n".join(decompiled_code.values())
    logger.debug(f"Attempting to compile and run tests for problem: {problem_id}")

    async def check_ans():
        try:
            compile_passed, test_passed = await new_problem.run_tests(
                compile_flags=["-Wno-implicit-function-declaration"]
            )
            if not compile_passed:
                logger.debug(f"Compilation failed for problem: {problem_id}")
                return EvalResult.COMPILE_FAIL

            if test_passed:
                logger.debug(f"Tests passed for problem: {problem_id}")
                return EvalResult.OK
            else:
                logger.debug(f"Tests failed for problem: {problem_id}")
                return EvalResult.TEST_FAIL
        except RuntimeError:
            logger.debug(f"Runtime error during compile/test for problem: {problem_id}")
            return EvalResult.COMPILE_FAIL

    res = await check_ans()
    if qid is not None:
        await client["llm_ans_log"].update_one(
            {"_id": "-".join((problem.id, model_name, optLevel, str(qid)))},
            {
                "$set": {
                    "problem_id": problem.id,
                    "model_name": model_name,
                    "optLevel": optLevel,
                    "qid": qid,
                    "ans": new_problem.func_def
                    if isinstance(new_problem, ExeBenchProblem)
                    else new_problem.code,
                    "result": res.value,
                }
            },
            upsert=True,
        )
    return res


async def eval_all_oj_problems(optLevel: str, model_name: str):
    problem_id_list: list[str] = []
    async with open(os.path.join(PROJECT_ROOT, "tmp", "eval_list.txt")) as f:
        async for line in f:
            striped_line = line.strip()
            if len(striped_line) != 0:
                problem_id_list.append(striped_line)
    p = get_progress_bar(console)
    p.start()
    task = p.add_task("eval", total=len(problem_id_list))
    for probliem_id in problem_id_list:
        row = await client["oj_problems"].find_one(
            {"id": probliem_id}, projection={"_id": 0}
        )
        problem = OjProblem.model_validate(row)
        res = await eval_problem(problem, optLevel, model_name, None)
        async with open(os.path.join(PROJECT_ROOT, "tmp", "eval_result.csv"), "a") as f:
            await f.write(f"{model_name},{optLevel},{problem.id},{res.value}\n")
        p.update(task, advance=1)


async def eval_all_exebench_problems(
    optLevel: str, model_name: str, total_times: int = 20
):
    total = await client["exebench"].count_documents({"label": "real_test"})
    stats: dict[EvalResult, int] = {v: 0 for v in EvalResult}
    p = get_progress_bar()
    task = p.add_task("eval", total=total)

    def get_table() -> Table:
        table = Table(box=box.SIMPLE)
        for v in EvalResult:
            table.add_column(
                v.value,
                justify="right",
                style="green" if v.value == "OK" else "yellow",
                no_wrap=True,
            )
        table.add_row(*[str(stats[v]) for v in EvalResult])
        total_count = sum(stats.values())
        if total_count == 0:
            table.add_row(*["NaN" for _ in EvalResult])
        else:
            table.add_row(*[f"{100 * stats[v] / total_count:.2f}%" for v in EvalResult])
        return table

    wrong_counts = []
    compile_fail_counts = []

    def get_passk_table() -> Table:
        table = Table(box=box.SIMPLE)
        table.add_column("", style="yellow", no_wrap=True)
        visable_k = [i for i in range(1, total_times + 1) if i == 1 or i % 5 == 0]
        for v in visable_k:
            table.add_column(
                f"Pass@{v}",
                justify="right",
                style="green",
                no_wrap=True,
            )
        passk = wrong_count_to_passk(wrong_counts, total_times, visable_k)
        recompilable_passk = wrong_count_to_passk(
            compile_fail_counts, total_times, visable_k
        )
        table.add_row("Rerunable", *[f"{100 * v:.2f}%" for v in passk])
        table.add_row("Recompilable", *[f"{100 * v:.2f}%" for v in recompilable_passk])
        return table

    group = Group(p, get_table(), get_passk_table())

    with Live(group, console=console) as live:
        worker_number = len(local_api_client) * 3
        queue: asyncio.Queue = asyncio.Queue(worker_number)

        async def worker():
            while True:
                row = await queue.get()
                try:
                    this_correct_count = 0
                    this_compile_ok_count = 0
                    for i in range(total_times):
                        try:
                            problem = ExeBenchProblem.model_validate(row)
                            if model_name in (
                                "llm4decompile-1.3b-v1.5",
                                "llm4decompile-6.7b-v1.5",
                            ):
                                collection = "llm4decompile_function"
                                template_file = "llm4decompile.jinja"
                            elif model_name in (
                                "llm4decompile-1.3b-v2",
                                "llm4decompile-6.7b-v2",
                            ):
                                collection = "functions"
                                template_file = "llm4decompile-v2.jinja"
                            else:
                                collection = "functions"
                                template_file = "prompt.jinja"
                            res = await eval_problem(
                                problem,
                                optLevel,
                                model_name,
                                i,
                                collection,
                                template_file,
                            )
                            stats[res] += 1
                            if res == EvalResult.OK:
                                this_correct_count += 1
                                this_compile_ok_count += 1
                            elif res == EvalResult.TEST_FAIL:
                                this_compile_ok_count += 1
                        except Exception:
                            logger.exception(f"eval {row['id']} failed")
                    wrong_counts.append(total_times - this_correct_count)
                    compile_fail_counts.append(total_times - this_compile_ok_count)
                finally:
                    queue.task_done()
                    p.update(task, advance=1)
                    live.update(Group(p, get_table(), get_passk_table()))

        workers = [asyncio.create_task(worker()) for _ in range(worker_number)]
        session = client.client.start_session()
        await client["llm_ans_log"].delete_many(
            {
                "model_name": model_name,
                "optLevel": optLevel,
            },
        )
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
    passk = wrong_count_to_passk(wrong_counts, total_times)
    recompilable_passk = wrong_count_to_passk(compile_fail_counts, total_times)

    async with open("tmp/eval_passk.tex", "a") as f:
        await f.write(f"{model_name} & {optLevel} & rerunable & ")
        await f.write(" & ".join(([f"{100 * v:.2f}\\%" for v in passk])))
        await f.write("\n")

        await f.write(f"{model_name} & {optLevel} & recompilable & ")
        await f.write(" & ".join(([f"{100 * v:.2f}\\%" for v in recompilable_passk])))
        await f.write("\n")

    async with open("tmp/eval_result_type.tex", "a") as f:
        if await f.tell() == 0:
            await f.write("model_name & optLevel & ")
            await f.write(" & ".join([v.value for v in EvalResult]) + "\n")
        await f.write(f"{model_name} & {optLevel} & ")
        total_count = sum(stats.values())
        if total_count == 0:
            await f.write(" & ".join(["NaN" for _ in EvalResult]))
        else:
            await f.write(
                " & ".join(
                    [f"{100 * stats[v] / total_count:.2f}\\%" for v in EvalResult]
                )
            )
        await f.write("\n")


async def find_rl_exebench_problems(
    optLevel: str, model_name: str, total_times: int = 3
):
    sample_size = 50000
    size_begin = 100
    size_end = 500
    p = get_progress_bar()
    task = p.add_task("eval", total=sample_size)

    correct_counts = {v: 0 for v in range(0, total_times + 1)}

    def get_acc_table() -> Table:
        table = Table(box=box.SIMPLE)
        for v in range(0, total_times + 1):
            table.add_column(
                f"Acc={v}/{total_times}",
                justify="right",
                style="green",
                no_wrap=True,
            )
        table.add_row(*[str(correct_counts[v]) for v in range(0, total_times + 1)])
        return table

    group = Group(p, get_acc_table())

    with Live(group, console=console) as live:
        queue: asyncio.Queue = asyncio.Queue(8)

        async def worker():
            while True:
                problem_id = (await queue.get())["binary"]
                row = await client["exebench"].find_one({"id": problem_id})
                if row is None:
                    continue
                this_correct_count = 0
                for _ in range(total_times):
                    try:
                        problem = ExeBenchProblem.model_validate(row)
                        res = await eval_problem(problem, optLevel, model_name, None)
                        if res == EvalResult.OK:
                            this_correct_count += 1
                    except Exception:
                        logger.exception(f"eval {row['id']} failed")
                correct_counts[this_correct_count] += 1
                if 1 <= this_correct_count <= 2:
                    async with open("tmp/rl_problem_list.txt", "a") as f:
                        await f.write(problem_id + "," + optLevel + "\n")
                queue.task_done()
                p.update(task, advance=1)
                live.update(Group(p, get_acc_table()))

        workers = [asyncio.create_task(worker()) for _ in range(8)]
        session = client.client.start_session()

        async for row in await client["functions"].aggregate(
            [
                {
                    "$match": {
                        "source_code": {"$exists": True},
                        "optLevel": optLevel,
                        "$expr": {
                            "$and": [
                                {"$not": [{"$in": ["$source_code", [None, ""]]}]},
                                {"$lt": [{"$strLenCP": "$asm"}, size_end]},
                                {"$gte": [{"$strLenCP": "$asm"}, size_begin]},
                                {
                                    "$regexMatch": {
                                        "input": "$binary",
                                        "regex": "^train_real_simple_io-||^train_real_compilable-",
                                    }
                                },
                            ]
                        },
                    }
                },
                {"$sample": {"size": sample_size}},
                {"$project": {"binary": 1, "_id": 0}},
            ],
            session=session,
        ):
            await queue.put(row)
            await client.command("refreshSessions", [session.session_id])
        await session.end_session()
        await queue.join()

        p.stop()
        for w in workers:
            w.cancel()


async def main():
    models = [("llm4decompile-1.3b-v1.5", False)]

    for model, need_load_lora in models:
        logger.info("start to evaluation model " + model)
        if need_load_lora:
            logger.info("load model " + model)
            await local_api_client.load_lora_module(model)
        for optLevel in ["O0", "O1", "O2", "O3", "Os"]:
            async with open("tmp/eval_passk.tex", "r") as f:
                async for line in f:
                    if line.startswith(f"{model} & {optLevel} &"):
                        logger.info(
                            f"model {model} optLevel {optLevel} already evaluated, skip"
                        )
                        break
                else:
                    logger.info(f"eval model {model} for {optLevel}")
                    await eval_all_exebench_problems(optLevel, model, 1)
        if need_load_lora:
            logger.info("unload model " + model)
            await local_api_client.unload_lora_module(model)


if __name__ == "__main__":
    console = init_log("INFO")
    asyncio.run(main())
