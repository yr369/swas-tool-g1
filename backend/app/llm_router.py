"""
llm_router.py
Rate-limited router across multiple LLM backends for SWAS.

Buckets:
  - gemini_1, gemini_2, gemini_3   (Gemini API, separate keys/quotas)
  - nvidia_deepseek                (deepseek-ai/deepseek-v4-flash, 40 rpm)
  - nvidia_glm                     (z-ai/glm-5.2, 40 rpm)
  - nvidia_llama                   (meta/llama-3.3-70b-instruct, 40 rpm)

Strategy: token-bucket per backend, round-robin selection of the
least-recently-used backend that has capacity. If all are saturated,
queue and wait for the soonest-available slot instead of failing.
"""

import time
import threading
from dataclasses import dataclass, field
from collections import deque
from typing import Callable, Optional


@dataclass
class Backend:
    name: str
    call_fn: Callable[[str], str]      # actual API call, takes prompt -> response text
    rpm_limit: int
    call_times: deque = field(default_factory=deque)  # timestamps of last calls
    lock: threading.Lock = field(default_factory=threading.Lock)

    def available_in(self) -> float:
        """Seconds until this backend has a free slot. 0 if free now."""
        now = time.time()
        with self.lock:
            # drop timestamps older than 60s
            while self.call_times and now - self.call_times[0] > 60:
                self.call_times.popleft()
            if len(self.call_times) < self.rpm_limit:
                return 0.0
            return 60 - (now - self.call_times[0])

    def record_call(self):
        with self.lock:
            self.call_times.append(time.time())


class LLMRouter:
    def __init__(self, backends: list[Backend]):
        self.backends = backends
        self._rr_index = 0
        self._rr_lock = threading.Lock()

    def _pick_backend(self) -> Backend:
        """Pick the backend with the soonest availability, round-robin among ties."""
        with self._rr_lock:
            n = len(self.backends)
            best = None
            best_wait = None
            for offset in range(n):
                idx = (self._rr_index + offset) % n
                b = self.backends[idx]
                wait = b.available_in()
                if wait == 0.0:
                    self._rr_index = (idx + 1) % n
                    return b
                if best_wait is None or wait < best_wait:
                    best, best_wait = b, wait
            # nothing free right now — wait for the soonest one
            time.sleep(min(best_wait, 5))  # cap sleep, re-check loop by caller
            return self._pick_backend()

    def call(self, prompt: str, prefer: Optional[str] = None, max_retries: int = 2) -> tuple[str, str]:
        """
        Returns (response_text, backend_name_used).
        prefer: backend name to try first (e.g. pin gate-checks to nvidia_llama
                to save Gemini quota for triage), falls back to router if busy.
        """
        if prefer:
            for b in self.backends:
                if b.name == prefer and b.available_in() == 0.0:
                    try:
                        result = b.call_fn(prompt)
                        b.record_call()
                        return result, b.name
                    except Exception:
                        pass  # fall through to router

        last_err = None
        for _ in range(max_retries + 1):
            b = self._pick_backend()
            try:
                result = b.call_fn(prompt)
                b.record_call()
                return result, b.name
            except Exception as e:
                last_err = e
                continue
        raise RuntimeError(f"All backends failed. Last error: {last_err}")


# ---- Example wiring (fill in your actual client calls) ----
#
# def gemini_call_1(prompt): return gemini_client_1.generate(prompt)
# def gemini_call_2(prompt): return gemini_client_2.generate(prompt)
# def gemini_call_3(prompt): return gemini_client_3.generate(prompt)
# def nvidia_deepseek_call(prompt): return nvidia_client.chat(model="deepseek-ai/deepseek-v4-flash", prompt=prompt)
# def nvidia_glm_call(prompt): return nvidia_client.chat(model="z-ai/glm-5.2", prompt=prompt)
# def nvidia_llama_call(prompt): return nvidia_client.chat(model="meta/llama-3.3-70b-instruct", prompt=prompt)
#
# router = LLMRouter([
#     Backend("gemini_1", gemini_call_1, rpm_limit=15),   # set to your actual Gemini free/paid tier rpm
#     Backend("gemini_2", gemini_call_2, rpm_limit=15),
#     Backend("gemini_3", gemini_call_3, rpm_limit=15),
#     Backend("nvidia_deepseek", nvidia_deepseek_call, rpm_limit=40),
#     Backend("nvidia_glm", nvidia_glm_call, rpm_limit=40),
#     Backend("nvidia_llama", nvidia_llama_call, rpm_limit=40),
# ])
#
# Usage in your pipeline phases:
#   gate_result, backend_used = router.call(gate_prompt, prefer="nvidia_llama")
#   triage_result, backend_used = router.call(triage_prompt, prefer="gemini_1")
