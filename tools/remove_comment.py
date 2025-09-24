import asyncio
import os

from pymongo import AsyncMongoClient

from lib.code_analysis import normalize_code
from lib.utils import get_progress_bar, init_log


async def main():
    client = AsyncMongoClient(os.environ["MONGODB"])["decompile"]
    console = init_log("WARNING")
    p = get_progress_bar(console)
    p.start()

    filter = {}
    func_collection = client["functions"]
    t = p.add_task("functions", total=await func_collection.count_documents(filter))
    async for row in func_collection.find(
        filter, projection={"source_code": True}, batch_size=128
    ):
        code = await normalize_code(row["source_code"])
        if code != row["source_code"]:
            await func_collection.update_one(
                {"_id": row["_id"]},
                {"$set": {"source_code": code}},
            )
        p.update(t, advance=1)
    p.stop_task(t)

    filter = {}
    exebenches_collection = client["exebench"]
    t = p.add_task(
        "exebenches", total=await exebenches_collection.count_documents(filter)
    )
    async for row in exebenches_collection.find(
        filter, projection={"func_def": True}, batch_size=128
    ):
        code = await normalize_code(row["func_def"])
        if code != row["func_def"]:
            await exebenches_collection.update_one(
                {"_id": row["_id"]},
                {"$set": {"func_def": code}},
            )
        p.update(t, advance=1)
    p.stop_task(t)


if __name__ == "__main__":
    asyncio.run(main())
