from peft import PeftModel
from transformers.models.auto.modeling_auto import AutoModelForCausalLM
from transformers.models.auto.tokenization_auto import AutoTokenizer

BASE_DIR = "./models/"
base_model_id = BASE_DIR + "base_model"
adaptor_id = BASE_DIR + "adaptor"

base_model_reload = AutoModelForCausalLM.from_pretrained(
    base_model_id,
    device_map="auto",
)
peft_model = PeftModel.from_pretrained(base_model_reload, adaptor_id)
peft_model = peft_model.merge_and_unload()  # type: ignore

tokenizer_reload = AutoTokenizer.from_pretrained(base_model_id)
tokenizer_reload.padding_side = "right"
if tokenizer_reload.pad_token is None:
    tokenizer_reload.pad_token = tokenizer_reload.eos_token

merge_model_id = BASE_DIR + "output"

# Save the merged model and tokenizer
peft_model.save_pretrained(merge_model_id)
tokenizer_reload.save_pretrained(merge_model_id)
