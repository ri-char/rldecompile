import time

import datasets
from datasets import DatasetDict, load_dataset
from peft import LoraConfig
from transformers.models.auto.modeling_auto import AutoModelForCausalLM
from transformers.models.auto.tokenization_auto import AutoTokenizer
from transformers.trainer_utils import get_last_checkpoint
from trl.trainer.sft_config import SFTConfig
from trl.trainer.sft_trainer import SFTTrainer

LOAD_CHECKPOINT = False
device_string = "auto"

model_id = "Qwen2.5-Coder-3B"
# model_id = "llm4decompile-1.3b-v1.5"
model_name = model_id + "-lora-" + time.strftime("%Y-%m-%d-%H-%M-%S")

# 加载模型
model = AutoModelForCausalLM.from_pretrained(
    model_id,
)

# 加载分词器
tokenizer = AutoTokenizer.from_pretrained(model_id)
tokenizer.padding_side = "right"
# 设置 padding token
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token


dataset: DatasetDict = load_dataset("json", data_files="instructs_full.json")  # type: ignore

checkpoint_path = model_name + "-checkpoint"

if LOAD_CHECKPOINT:
    last_checkpoint = get_last_checkpoint(checkpoint_path)
else:
    last_checkpoint = None

trainer = SFTTrainer(
    model=model,
    train_dataset=dataset[datasets.Split.TRAIN],
    args=SFTConfig(
        output_dir=checkpoint_path,  # 训练输出目录
        num_train_epochs=2,  # 训练轮次
        per_device_train_batch_size=1,  # 每个设备的批大小
        gradient_accumulation_steps=1,  # 梯度累积步数
        learning_rate=2e-5,  # 学习率
        logging_steps=10,  # 每隔多少步记录一次日志
        save_steps=1000,  # 每隔多少步保存一次模型
        lr_scheduler_type="cosine",  # 学习率调度器类型,
        max_length=2000,
    ),
    peft_config=LoraConfig(
        r=32,
        lora_alpha=32,
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

trainer.train(resume_from_checkpoint=last_checkpoint)
trainer.save_model(model_name)
