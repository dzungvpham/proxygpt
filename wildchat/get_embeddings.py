import itertools
import numpy as np
import os
import pyarrow.dataset as ds
import threading
import time

from collections import deque
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from dotenv import load_dotenv
from google import genai
from google.genai.types import EmbedContentConfig, HttpOptions
from google.oauth2 import service_account
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from tqdm import tqdm

load_dotenv()

credentials = service_account.Credentials.from_service_account_file(
    os.environ.get("GGL_SERVICE_ACC_FILE"),
    scopes=["https://www.googleapis.com/auth/cloud-platform"],
)
ggl_project_id = credentials.project_id
vertex_ai_client = genai.Client(
    vertexai=True,
    project=ggl_project_id,
    location="us-central1",
    credentials=credentials,
    http_options=HttpOptions(api_version="v1"),
)

MODEL = "gemini-embedding-001"
OUTPUT_DIR = "./wildchat_embeddings/wildchat_" + MODEL

API_BATCH = 250
EMBED_DIM = 768
MAX_WORKERS = 32
MAX_TOKENS_PER_MIN = 4_500_000


def estimate_tokens(text):
    return max(1, len(text) // 4)


class TokenRateLimiter:
    def __init__(self, max_tokens_per_min):
        self.max_tokens = max_tokens_per_min
        self.events = deque()
        self.lock = threading.Lock()
 
    def acquire(self, tokens):
        """Reserve tokens before an API call (using an estimate)."""
        while True:
            with self.lock:
                now = time.time()
                while self.events and now - self.events[0][0] > 60:
                    self.events.popleft()
                used_tokens = sum(t for _, t in self.events)
                if used_tokens + tokens <= self.max_tokens:
                    self.events.append((now, tokens))
                    return
            time.sleep(0.05)
 
    def correct(self, estimated, actual):
        """Replace the estimated token count with the actual count from the API response."""
        with self.lock:
            # walk backwards to find the matching event and update it
            for i in range(len(self.events) - 1, -1, -1):
                if self.events[i][1] == estimated:
                    self.events[i] = (self.events[i][0], actual)
                    return

SKIP = 0
def batch_texts(dataset):
    batch = []
    start_idx = SKIP
    row_idx = 0

    scanner = dataset.scanner(columns=["conversation"], batch_size=5000)

    for record_batch in scanner.to_batches():
        conv_col = record_batch.column(0)
        if row_idx + len(conv_col) < SKIP:
            row_idx += len(conv_col)
            continue

        for conv in conv_col:
            if row_idx < SKIP:
                row_idx += 1
                continue

            conv = conv.as_py()

            user_texts = [t["content"] for t in conv if t.get("role") == "user" and "content" in t]
            joined = "\n===\n".join(user_texts)

            if not joined:
                assistant_texts = [t["content"] for t in conv if t.get("role") == "assistant" and "content" in t]
                joined = "\n===\n".join(assistant_texts)

            batch.append((row_idx, joined))

            if len(batch) == API_BATCH:
                yield (start_idx, batch)
                batch = []
                start_idx += API_BATCH

            row_idx += 1

    if batch:
        yield (start_idx, batch)

token_limiter = TokenRateLimiter(MAX_TOKENS_PER_MIN)


def log_retry_error(retry_state):
    exception = retry_state.outcome.exception()
    print(f"[Embed API Retry] Attempt {retry_state.attempt_number} failed: {exception}")

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=60),
    retry=retry_if_exception_type(Exception),
    before_sleep=log_retry_error,
    reraise=True,
)
def _call_embed_api(texts):
    return vertex_ai_client.models.embed_content(
        model=MODEL,
        contents=texts,
        config=EmbedContentConfig(
            task_type="CLUSTERING",
            output_dimensionality=EMBED_DIM,
        ),
    )

def embed_and_save(batch_info):
    start_idx, batch = batch_info
    embeddings = []
    for _, text in batch:
        text = text[:20000]
        estimated = estimate_tokens(text)
        token_limiter.acquire(estimated)
        response = _call_embed_api([text])
        actual = int(response.embeddings[0].statistics.token_count)
        token_limiter.correct(estimated, actual)
        embeddings.append(response.embeddings[0].values)

    embeddings = np.array(embeddings, dtype=np.float32)
    np.save(os.path.join(OUTPUT_DIR, f"shard_{start_idx}.npy"), embeddings)

    return start_idx, len(embeddings)


# main pipeline
os.makedirs(OUTPUT_DIR, exist_ok=True)

dataset = ds.dataset(
    "/datasets/ai/allenai/hub/datasets--allenai--WildChat-4.8M/snapshots/c827c6df8fcf008219ffaffa4d1dd77491099367/data",
    format="parquet",
)

with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    batch_iter = iter(batch_texts(dataset))
    futures = {}

    for batch_info in itertools.islice(batch_iter, MAX_WORKERS):
        futures[executor.submit(embed_and_save, batch_info)] = batch_info

    with tqdm() as pbar:
        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)

            for future in done:
                try:
                    start_idx, count = future.result()
                except Exception as e:
                    failed_batch = futures.pop(future)
                    print(f"Batch at row {failed_batch[0]} failed after retries: {e}")
                    continue

                del futures[future]
                pbar.update(count)

                next_batch = next(batch_iter, None)
                if next_batch:
                    futures[executor.submit(embed_and_save, next_batch)] = next_batch