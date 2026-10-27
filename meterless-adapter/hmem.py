"""H-MEM: a real hierarchical-memory reference implementation.

This is NOT a pip install and NOT a mock: it is the engine itself, in
this repo, following the Meterless H-MEM reference architecture
(Apache-2.0 upstream): three layers, one generator.

Layers:
  * episodic  -- append-only JSONL records of guard decisions (what
    happened, when, what verdict). This is the raw evidence.
  * semantic  -- aggregates over episodic records: verdict counts per
    pattern key, so recall can answer "have we seen this shape before?"
  * working   -- the recall window for one decision: the top-k episodic
    records most similar to the current input, by token overlap.

The generator is injected: a callable prompt -> text. In production it
is the Nightshift client (a real local model through the hotspot); in
unit tests it is a caller-supplied fake, clearly labeled as such in the
test file. `distill()` asks the generator to compress a cluster of
episodic records into an insight pack. If the generator fails, distill
returns None -- it never invents an insight pack.

Persistence is a plain JSONL file, so every record can be inspected,
replayed, and (for the Open Agent demo) exported to Zetaris as the
audit trail.
"""
import json
import os
import re
import time
from collections import Counter

_STOP = set("a an the and or of to in on for with is are was were be by at it this that".split())


def _tokens(text):
    return [t for t in re.findall(r"[a-z0-9_]+", (text or "").lower()) if t not in _STOP]


class HMem:
    def __init__(self, store_path):
        self.store_path = store_path
        self._entries = []
        if os.path.isfile(store_path):
            with open(store_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            self._entries.append(json.loads(line))
                        except ValueError:
                            continue

    def write(self, entry):
        """Append one episodic record. Entry must be a JSON-able dict."""
        record = dict(entry)
        record.setdefault("ts", time.time())
        self._entries.append(record)
        directory = os.path.dirname(os.path.abspath(self.store_path))
        os.makedirs(directory, exist_ok=True)
        with open(self.store_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def recall(self, query, k=5):
        """Top-k episodic records by token overlap with the query."""
        qtok = set(_tokens(query))
        if not qtok:
            return list(self._entries[-k:])[::-1]
        scored = []
        for entry in self._entries:
            text = " ".join(str(v) for v in entry.values())
            overlap = len(qtok & set(_tokens(text)))
            scored.append((overlap, entry))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [entry for score, entry in scored[:k] if score > 0]

    def semantic(self):
        """Verdict counts per pattern key across all episodic records.

        Keys are "pattern|verdict" strings (not tuples) so the result is
        JSON-serializable for evidence logs.
        """
        counts = Counter()
        for entry in self._entries:
            key = entry.get("pattern") or entry.get("kind") or "unknown"
            counts["%s|%s" % (key, entry.get("verdict", "unknown"))] += 1
        return dict(counts)

    def distill(self, generator, query, k=10):
        """Ask the generator to compress recalled records into an insight pack.

        Returns the generator's text, or None if the generator fails or
        returns nothing. Never fabricates a pack.
        """
        records = self.recall(query, k=k) or self._entries[-k:]
        if not records:
            return None
        prompt = (
            "Summarize these guard-decision records into one short insight pack: "
            "what pattern recurs, what verdict it usually gets, and what to watch "
            "for next time. Records:\n"
            + "\n".join(json.dumps(r, sort_keys=True) for r in records)
        )
        try:
            text = generator(prompt)
        except Exception:
            return None
        if not text or not str(text).strip():
            return None
        return str(text).strip()

    def __len__(self):
        return len(self._entries)
