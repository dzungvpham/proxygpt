import pandas as pd
import spacy
import stylo_metrix as sm

MAX_LEN = 2048
lang = "English"
langcode = "en"

assert spacy.require_gpu(), "Spacy cannot use GPU!"

df = pd.read_csv("wildchat_filtered_4o20240806_41mini20250414_device_deduped.csv")
df = df[df["language"] == lang]
df = df[df.groupby(["hashed_ip", "accept_language", "device_info"])["model"]
    .transform("nunique")
    .ge(2)
]
conversations = df["conversation"].to_list()
conversations = [c[:MAX_LEN] for c in conversations]

stylo = sm.StyloMetrix(langcode)
style_embeddings = stylo.transform(conversations)
style_embeddings.to_csv(f"wildchat_embeddings/wildchat_filtered_{langcode}_{MAX_LEN}_stylometrix.csv", index=False)