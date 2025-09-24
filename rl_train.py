import os
import time

import httpx
import torch
from datasets import DatasetDict, load_dataset
from peft import LoraConfig
from transformers.models.auto.modeling_auto import AutoModelForCausalLM
from transformers.models.auto.tokenization_auto import AutoTokenizer
from transformers.trainer_utils import get_last_checkpoint
from trl.trainer.grpo_config import GRPOConfig
from trl.trainer.grpo_trainer import GRPOTrainer

LOAD_CHECKPOINT = False

s = httpx.Client(http2=True, http1=False, timeout=httpx.Timeout(None))


def reward_func(
    prompts: list[str],
    completions: list[str],
    completion_ids: list[list[int]],
    binary_id: list[str],
    **reward_kwargs,
) -> list[float] | None:
    result: list[float] = []
    for completion, binary in zip(completions, binary_id):
        try:
            r = s.post(
                "https://rl-server/reward",
                json={
                    "completion": completion,
                    "problem_id": binary,
                    "key": os.environ["RL_SERVER_KEY"],
                },
            )
            if r.status_code != 200:
                print(f"status code: {r.status_code}, response: {r.text}")
                return None
                # result.append(0)
                # continue
            reward = r.json()
            assert isinstance(reward, (float, int))
            result.append(reward)
        except Exception as e:
            print(e)
            # result.append(0)
            return None
    return result


model_id = "Qwen2.5-Coder-3B-lora-v1"
model_name = model_id + "-grpo-" + time.strftime("%Y-%m-%d-%H-%M-%S")

# 加载模型
model = AutoModelForCausalLM.from_pretrained(model_id, torch_dtype=torch.bfloat16)

# 加载分词器
tokenizer = AutoTokenizer.from_pretrained(model_id)
tokenizer.padding_side = "right"
# 设置 padding token
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token


dataset: DatasetDict = load_dataset("json", data_files="instructs_rl.json")  # type: ignore

checkpoint_path = model_name + "-checkpoint"

if LOAD_CHECKPOINT:
    last_checkpoint = get_last_checkpoint(checkpoint_path)
else:
    last_checkpoint = None

training_args = GRPOConfig(
    output_dir=checkpoint_path,
    logging_steps=10,
    max_completion_length=1024,
    max_prompt_length=1024,
    per_device_train_batch_size=1,
    num_generations=4,
    save_steps=500,
    gradient_accumulation_steps=1,
    # use_vllm=True,
    # vllm_mode="colocate",
    use_vllm=False,
    # vllm_mode="server",
    # vllm_server_host="192.168.5.187",
    # vllm_server_port=8000,
    learning_rate=1e-7,
    bf16=True,
    generation_kwargs={},
    mask_truncated_completions=True,
    # log_completions=True,
)
trainer = GRPOTrainer(
    model=model,
    reward_funcs=reward_func,  # type: ignore
    train_dataset=dataset["train"],
    args=training_args,
    peft_config=LoraConfig(
        r=16,
        lora_alpha=16,
        target_modules=[
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
            "gate_proj",
            "up_proj",
            "down_proj",
        ],
        lora_dropout=0.1,
        bias="none",
    ),
)

try:
    trainer.train(resume_from_checkpoint=last_checkpoint)
except KeyboardInterrupt:
    trainer.save_model(model_name + "-interrupt")
    raise
trainer.save_model(model_name)
