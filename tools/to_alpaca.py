import asyncio
import json
import random

from lib.utils import client, init_jinja_env


def get_aggregate_query(size_begin: int, size_end: int, sample_size: int = 50000):
    return [
        {
            "$match": {
                "source_code": {"$exists": True},
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
    ]


async def main():
    env = init_jinja_env()
    alpaca = []
    func_collection = client["functions"]
    temp = env.get_template("prompt.jinja")

    sample_args = [
        (0, 100, 50000),
        (100, 200, 50000),
        (200, 300, 50000),
        (300, 400, 50000),
        (400, 500, 50000),
        (500, 1000, 20000),
    ]
    for arg in sample_args:
        async for row in await func_collection.aggregate(get_aggregate_query(*arg)):
            assert "source_code" in row
            prompt = temp.render(**row)
            alpaca.append(
                {
                    "prompt": prompt,
                    "completion": row["source_code"],
                    "binary_id": row["binary"],
                }
            )
    random.shuffle(alpaca)
    print("exported", len(alpaca))
    with open("tmp/instructs_full.json", "w") as f:  # noqa: ASYNC230
        json.dump(alpaca, f, ensure_ascii=False, separators=(",", ":"))

    sample_args = [
        (0, 100, 2500),
        (100, 200, 2500),
        (200, 300, 2500),
        (300, 400, 2500),
        (400, 500, 2500),
    ]
    for arg in sample_args:
        async for row in await func_collection.aggregate(get_aggregate_query(*arg)):
            assert "source_code" in row
            prompt = temp.render(**row)
            alpaca.append(
                {
                    "prompt": prompt,
                    "completion": row["source_code"],
                    "binary_id": row["binary"],
                }
            )
    print("exported to rl dataset", len(alpaca))
    with open("tmp/instructs_rl.json", "w") as f:  # noqa: ASYNC230
        json.dump(alpaca, f, ensure_ascii=False, separators=(",", ":"))

    queue: asyncio.Queue = asyncio.Queue(8)
    lock: asyncio.Lock = asyncio.Lock()

    async def worker():
        while True:
            id, opt = await queue.get()
            print(id, opt)
            async for row in func_collection.find({"binary": id, "optLevel": opt}):
                if "source_code" not in row:
                    continue
                prompt = temp.render(**row)
                async with lock:
                    alpaca.append(
                        {
                            "prompt": prompt,
                            "completion": row["source_code"],
                            "binary_id": row["binary"],
                        }
                    )
                queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(8)]

    with open("tmp/rl_problem_list_sort.txt", "r") as f:  # noqa: ASYNC230
        for line in f:
            id, opt = line.strip().split(",")
            await queue.put((id, opt))
    await queue.join()

    for w in workers:
        w.cancel()

    random.shuffle(alpaca)

    print("exported to rl dataset", len(alpaca))
    with open("tmp/instructs_rl_o1.json", "w") as f:  # noqa: ASYNC230
        json.dump(alpaca, f, ensure_ascii=False, separators=(",", ":"))


if __name__ == "__main__":
    asyncio.run(main())
