import os
import pandas as pd
from datasets import load_dataset
from tqdm import tqdm

DATASET_PATH = "/datasets/ai/allenai/hub/datasets--allenai--WildChat-4.8M"
OUTPUT_DIR = "./wildchat_preprocessed"
BATCH_SIZE = 10000
TURN_DELIM = "\n===\n"

os.makedirs(OUTPUT_DIR, exist_ok=True)

ds = load_dataset(DATASET_PATH, split="train", streaming=True)
print("Dataset loaded")

def batch_texts(ds):
    batch = []
    start_idx = 0
    with tqdm() as pbar:
        for idx, row in enumerate(ds):
            conv = row.get("conversation", [])
            user_texts = [t["content"] for t in conv if t.get("role") == "user" and "content" in t]
            joined = TURN_DELIM.join(user_texts)
            is_assistant = 0

            if not joined:
                assistant_texts = [t["content"] for t in conv if t.get("role") == "assistant" and "content" in t]
                joined = TURN_DELIM.join(assistant_texts)
                is_assistant = 1
            
            batch.append({
                "idx": idx,
                "conversation": joined.replace("\n", "\\n"),
                "is_assistant": is_assistant,
                "hashed_ip": row["hashed_ip"],
                "country": row["country"],
                "state": row["state"],
                "language": row["language"],
                "header": row["header"],
                "model": row["model"],
                "turn": row["turn"],
                "timestamp": row["timestamp"],
            })

            if len(batch) == BATCH_SIZE:
                pd.DataFrame(batch).to_csv(f"{OUTPUT_DIR}/shard_{start_idx}.csv", index=False)
                batch = []
                start_idx += 1
                pbar.update(BATCH_SIZE)

    if batch:
        pd.DataFrame(batch).to_csv(f"{OUTPUT_DIR}/shard_{start_idx}.csv", index=False)

batch_texts(ds)