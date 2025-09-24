import asyncio
from enum import Enum

import httpx
import openai
from loguru import logger


class LLMApiPool:
    _queue: asyncio.Queue[openai.AsyncOpenAI]
    endpoints: list[openai.AsyncOpenAI]
    size: int

    def __init__(self, devices: list[openai.AsyncOpenAI]):
        self._queue: asyncio.Queue[openai.AsyncOpenAI] = asyncio.Queue()
        for device in devices:
            self._queue.put_nowait(device)
        for device in devices:
            self._queue.put_nowait(device)
        self.endpoints = devices
        self.size = len(devices) * 2

    def __len__(self) -> int:
        return self.size

    async def call(self, content: str, model_id: str):
        api = await self._queue.get()
        try:
            return await api.chat.completions.create(
                model=model_id,
                messages=[{"role": "user", "content": content}],  # type: ignore
                max_tokens=10240,
            )
        finally:
            self._queue.put_nowait(api)

    async def load_lora_module(self, model_name: str):
        async def load(e: openai.AsyncOpenAI):
            res = await e._client.post(
                e._prepare_url("load_lora_adapter"),
                json={"lora_name": model_name, "lora_path": model_name},
                headers=e.auth_headers,
            )
            if (
                res.status_code == 400
                and "has already been loaded" in res.json()["message"]
            ):
                return
            res.raise_for_status()

        await asyncio.gather(*[load(e) for e in self.endpoints])

    async def unload_lora_module(self, model_name: str):
        async def unload(e: openai.AsyncOpenAI):
            res = await e._client.post(
                e._prepare_url("unload_lora_adapter"),
                json={"lora_name": model_name},
                headers=e.auth_headers,
            )
            if res.status_code == 404 and "cannot be found" in res.json()["message"]:
                return
            res.raise_for_status()

        await asyncio.gather(*[unload(e) for e in self.endpoints])


PROXY_URL = "socks5://192.168.21.57:20737"
local_api_client = LLMApiPool(
    [
        openai.AsyncOpenAI(
            base_url="http://192.168.5.187:8000/v1/",
            api_key="1",
            timeout=httpx.Timeout(300.0, connect=5.0),
        ),
        # openai.AsyncOpenAI(
        #     base_url="http://127.0.0.1:8000/v1/",
        #     api_key="1",
        #     timeout=httpx.Timeout(300.0, connect=5.0),
        #     http_client=httpx.AsyncClient(proxy=PROXY_URL),
        # ),
        # openai.AsyncOpenAI(
        #     base_url="http://127.0.0.1:8001/v1/",
        #     api_key="1",
        #     timeout=httpx.Timeout(300.0, connect=5.0),
        #     http_client=httpx.AsyncClient(proxy=PROXY_URL),
        # ),
        # openai.AsyncOpenAI(
        #     base_url="http://127.0.0.1:8002/v1/",
        #     api_key="1",
        #     timeout=httpx.Timeout(300.0, connect=5.0),
        #     http_client=httpx.AsyncClient(proxy=PROXY_URL),
        # ),
        # openai.AsyncOpenAI(
        #     base_url="http://127.0.0.1:8003/v1/",
        #     api_key="1",
        #     timeout=httpx.Timeout(300.0, connect=5.0),
        #     http_client=httpx.AsyncClient(proxy=PROXY_URL),
        # ),
    ]
)


class CallLLMError(Enum):
    INPUT_LENGTH_EXCEED = "INPUT_LENGTH_EXCEED"
    LENGTH_EXCEED = "LENGTH_EXCEED"
    API_ERROR = "API_ERROR"


async def call_llm(content: str, model_id: str) -> "str | CallLLMError":
    client = local_api_client
    retries = 2000
    while retries > 0:
        try:
            response = await client.call(content, model_id)
            choice = response.choices[0]
            finish_reason = choice.finish_reason
            if finish_reason not in ("stop", None):
                logger.debug(
                    f"Model did not stop normally. Finish reason: {finish_reason}"
                )
                return CallLLMError.LENGTH_EXCEED
            return choice.message.content or CallLLMError.API_ERROR
        except openai.OpenAIError as e:
            if isinstance(e, openai.APIStatusError) and 400 <= e.status_code < 500:
                if "This model's maximum context length is" in e.message:
                    logger.debug("Input length exceed")
                    return CallLLMError.INPUT_LENGTH_EXCEED
                else:
                    logger.exception("openai api error " + type(e).__name__)
                    break
            if retries > 1:
                logger.warning("openai api error " + type(e).__name__ + ", retrying...")
            else:
                logger.exception("openai api error " + type(e).__name__)
            retries -= 1
            await asyncio.sleep(1)
    return CallLLMError.API_ERROR
