import ast
import json
import pandas as pd
import pyarrow.dataset as ds
from tqdm import tqdm

# Make sure to change the path to your local copy
DATASET_PATH = "/datasets/ai/allenai/hub/datasets--allenai--WildChat-4.8M/snapshots/c827c6df8fcf008219ffaffa4d1dd77491099367/data"
dataset = ds.dataset(DATASET_PATH, format="parquet")
df = dataset.to_table(
    columns=["timestamp", "model", "hashed_ip", "header", "language", "country", "state"],
    filter=(
        (ds.field("model") == "gpt-4o-2024-08-06") |
        (ds.field("model") == "gpt-4.1-mini-2025-04-14")
    ),
).to_pandas()

# Extract device info from user agent
user_agents = dataset.to_table(columns=["header"]).to_pandas()
with open("user_agents.txt", "w") as f:
    all_uas = set([ua for d in user_agents["header"].to_list() if (ua := d["user-agent"]) is not None and len(ua) > 0])
    all_uas = sorted(list(all_uas))
    for ua in all_uas:
        f.write(ua + "\n")

with open("user_agents.txt", "r") as f:
    user_agents = f.readlines()
with open("parsed_user_agents.json", "r") as f:
    parsed_user_agents = json.load(f)

user_agent_map = {}
for ua, parsed in zip(user_agents, parsed_user_agents):
    ua = ua.strip()
    browser_name = parsed["browser"].get("name", "")
    if not browser_name:
        user_agent_map[ua] = ua.split("/")[0]
        continue

    device_info = parsed["device"]
    device_type = device_info.get("type", "")
    device = ""
    if len(device_type) > 0:
        device = "_".join([device_type, device_info.get("vendor", ""), device_info.get("model", "")])

    user_agent_map[ua] = ";".join([
        parsed["browser"].get("name", ""),
        parsed["os"].get("name", ""),
        device,
        parsed["cpu"].get("architecture", ""),
    ])

df["accept_language"] = df["header"].apply(lambda x: ast.literal_eval(x)["accept-language"])
df["user_agent"] = df["header"].apply(lambda x: ast.literal_eval(x)["user-agent"])
df["device_info"] = df["user_agent"].apply(lambda x: user_agent_map.get(x, "N/A"))
df["timestamp"] = pd.to_datetime(df["timestamp"])

# First filter to keep IDs with two models: GPT 4o 2024 08 06 and GPT 4.1 mini
groups = df.groupby(["hashed_ip"])["model"].nunique().ge(2)
valid_idx = set(groups[groups].index)
batches = []
model_filter = {"gpt-4o-2024-08-06", "gpt-4.1-mini-2025-04-14"}
for i in tqdm(range(320)):
    shard = pd.read_csv(f"wildchat_preprocessed/shard_{i}.csv")
    shard = shard[(shard["model"].isin(model_filter)) & shard["hashed_ip"].isin(valid_idx)]
    batches.append(shard)

# Keep only IDs with more than two models
df_filtered = pd.concat(batches, ignore_index=True).sort_values(["hashed_ip", "timestamp"])
df_filtered = df[df.groupby(["hashed_ip", "accept_language", "device_info"])["model"]
    .transform("nunique")
    .ge(2)
]
df_filtered = df_filtered.sort_values(["hashed_ip", "accept_language", "device_info", "timestamp"])
df_filtered = df_filtered.drop_duplicates("conversation")

# Filter based on prefixes and suffixes
min_len = 50
prefixes = {}
suffixes = {}

for idx, row in df_filtered.iterrows():
    conv = row["conversation"]
    identity = row["hashed_ip"] + "|" + row["accept_language"] + "|" + row["device_info"]
    model = row["model"]
    ts = row["timestamp"]
    text = conv.split("\n===\n", 1)[0]
    if len(text) < min_len:
        continue

    prefix = text[:min_len]
    if prefix in prefixes:
        prefixes[prefix]["indices"].append(idx)
        prefixes[prefix]["ids"].add(identity)
    else:
        prefixes[prefix] = {"indices": [idx], "ids": set([identity])}

    suffix = text[-min_len:]
    if suffix in suffixes:
        suffixes[suffix]["indices"].append(idx)
        suffixes[suffix]["ids"].add(identity)
    else:
        suffixes[suffix] = {"indices": [idx], "ids": set([identity])}

exclude_idx = set()
for data in [prefixes, suffixes]:
    for v in data.values():
        num_idx = len(v["indices"])
        num_ids = len(v["ids"])
        if num_ids > 1: # Exclude conversations shared by multiple IDs
            exclude_idx.update(v["indices"])
        elif num_idx >= 3: # Keep only three conversations with the same prefix/suffix
            exclude_idx.update(v["indices"][3:])

# Keep only IDs with more than two models
df_filtered = df_filtered[~df_filtered.index.isin(exclude_idx)]
df_filtered = df_filtered[df_filtered.groupby(["hashed_ip", "accept_language", "device_info"])["model"]
    .transform("nunique")
    .ge(2)
]
df_filtered = df_filtered.sort_values(["hashed_ip", "accept_language", "device_info", "timestamp"])
df_filtered.to_csv("wildchat_filtered_4o20240806_41mini20250414_device_deduped.csv", index=False)