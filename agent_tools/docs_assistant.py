#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


DEFAULT_INDEX_DIR = ".rag_index"
DEFAULT_MAX_CHARS = 2400
DEFAULT_OVERLAP_CHARS = 250
INDEX_VERSION = 1
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
TOKEN_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "can", "do", "for",
    "from", "how", "i", "in", "is", "it", "of", "on", "or", "the", "to",
    "use", "what", "when", "where", "with",
}
QUERY_EXPANSIONS = {
    "android": ("app", "vpn", "instrumentation"),
    "desktop": ("linux", "windows", "macos", "tray"),
    "mcp": ("agent_tools", "prepare_start", "workflow_status"),
    "rag": ("retrieval", "docs_assistant", "index", "search"),
    "ssh": ("home", "relay", "routing"),
    "precommit": ("prepush", "run_checks"),
}


@dataclass(frozen=True)
class DocChunk:
    id: str
    path: str
    heading_path: tuple[str, ...]
    line_start: int
    line_end: int
    text: str
    source_type: str

    @property
    def heading(self) -> str:
        return " > ".join(self.heading_path)

    @property
    def citation(self) -> str:
        return f"{self.path}:L{self.line_start}"

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "path": self.path,
            "heading_path": list(self.heading_path),
            "line_start": self.line_start,
            "line_end": self.line_end,
            "text": self.text,
            "source_type": self.source_type,
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "DocChunk":
        headings = value.get("heading_path", [])
        if not isinstance(headings, list):
            headings = []
        return cls(
            id=str(value["id"]),
            path=str(value["path"]),
            heading_path=tuple(str(item) for item in headings),
            line_start=int(value["line_start"]),
            line_end=int(value["line_end"]),
            text=str(value["text"]),
            source_type=str(value.get("source_type") or "public_docs"),
        )


@dataclass(frozen=True)
class SearchResult:
    chunk: DocChunk
    score: float
    lexical_score: float


@dataclass(frozen=True)
class IndexBuildResult:
    index_dir: Path
    file_count: int
    chunk_count: int


@dataclass(frozen=True)
class AnswerResult:
    answer: str
    results: tuple[SearchResult, ...]

    @property
    def citations(self) -> list[str]:
        return [result.chunk.citation for result in self.results]


def discover_markdown_files(root: str | Path = ".") -> list[Path]:
    root_path = Path(root).resolve()
    candidates = [root_path / "AGENTS.md", root_path / "README.md"]
    for directory in ("docs", "agent_docs"):
        base = root_path / directory
        if base.is_dir():
            candidates.extend(sorted(base.rglob("*.md")))
    candidates.append(root_path / "agent_tools" / "README.md")
    return sorted(
        {path.resolve() for path in candidates if path.is_file()},
        key=lambda path: path.relative_to(root_path).as_posix(),
    )


def build_docs_index(
    root: str | Path = ".",
    index_dir: str | Path = DEFAULT_INDEX_DIR,
    *,
    max_chars: int = DEFAULT_MAX_CHARS,
    overlap_chars: int = DEFAULT_OVERLAP_CHARS,
) -> IndexBuildResult:
    root_path = Path(root).resolve()
    index_path = _index_path(root_path, index_dir)
    files = discover_markdown_files(root_path)
    chunks: list[DocChunk] = []
    sources = []
    for path in files:
        chunks.extend(
            chunk_markdown_file(
                path,
                root_path,
                max_chars=max_chars,
                overlap_chars=overlap_chars,
            )
        )
        sources.append(
            {
                "path": path.relative_to(root_path).as_posix(),
                "sha256": _file_hash(path),
            }
        )
    index_path.mkdir(parents=True, exist_ok=True)
    _write_json(index_path / "index.json", {"chunks": [chunk.to_dict() for chunk in chunks]})
    _write_json(
        index_path / "manifest.json",
        {
            "version": INDEX_VERSION,
            "root": str(root_path),
            "source_files": sources,
            "file_count": len(files),
            "chunk_count": len(chunks),
        },
    )
    return IndexBuildResult(index_path, len(files), len(chunks))


def ensure_docs_index(
    root: str | Path = ".",
    index_dir: str | Path = DEFAULT_INDEX_DIR,
) -> tuple[IndexBuildResult | None, list[str]]:
    root_path = Path(root).resolve()
    index_path = _index_path(root_path, index_dir)
    warnings = index_freshness_warnings(root_path, index_path)
    if warnings:
        return build_docs_index(root_path, index_path), warnings
    return None, []


def index_freshness_warnings(
    root: str | Path = ".",
    index_dir: str | Path = DEFAULT_INDEX_DIR,
) -> list[str]:
    root_path = Path(root).resolve()
    index_path = _index_path(root_path, index_dir)
    manifest_path = index_path / "manifest.json"
    index_file = index_path / "index.json"
    if not manifest_path.is_file() or not index_file.is_file():
        return ["Documentation index is missing."]
    try:
        manifest = _read_json(manifest_path)
    except (ValueError, json.JSONDecodeError) as exc:
        return [f"Documentation index manifest is invalid: {exc}"]
    if int(manifest.get("version", 0)) != INDEX_VERSION:
        return ["Documentation index version changed."]
    recorded = manifest.get("source_files")
    if not isinstance(recorded, list):
        return ["Documentation index source manifest is missing."]
    expected = {
        path.relative_to(root_path).as_posix(): _file_hash(path)
        for path in discover_markdown_files(root_path)
    }
    actual = {
        str(item.get("path")): str(item.get("sha256"))
        for item in recorded
        if isinstance(item, dict)
    }
    return [] if actual == expected else ["Documentation sources changed after indexing."]


def chunk_markdown_file(
    path: str | Path,
    root: str | Path,
    *,
    max_chars: int = DEFAULT_MAX_CHARS,
    overlap_chars: int = DEFAULT_OVERLAP_CHARS,
) -> list[DocChunk]:
    source = Path(path).resolve()
    root_path = Path(root).resolve()
    rel_path = source.relative_to(root_path).as_posix()
    lines = source.read_text(encoding="utf-8").splitlines()
    sections = _sections(lines)
    chunks: list[DocChunk] = []
    for heading_path, line_start, line_end, section_text in sections:
        for part_index, part in enumerate(_split_text(section_text, max_chars, overlap_chars)):
            if not part.strip():
                continue
            digest = hashlib.sha1(
                f"{rel_path}:{line_start}:{part_index}:{part[:120]}".encode("utf-8")
            ).hexdigest()[:20]
            chunks.append(
                DocChunk(
                    id=digest,
                    path=rel_path,
                    heading_path=heading_path,
                    line_start=line_start,
                    line_end=line_end,
                    text=part.strip(),
                    source_type=_source_type(rel_path),
                )
            )
    return chunks


def search_docs(
    question: str,
    index_dir: str | Path = DEFAULT_INDEX_DIR,
    *,
    top_k: int = 3,
) -> list[SearchResult]:
    if top_k < 1 or top_k > 20:
        raise ValueError("top_k must be between 1 and 20")
    chunks = _load_chunks(Path(index_dir))
    query_tokens = _query_tokens(question)
    if not query_tokens:
        return []
    corpus = [tokenize(_search_text(chunk)) for chunk in chunks]
    raw_scores = _bm25_scores(query_tokens, corpus)
    max_score = max(raw_scores, default=0.0)
    results = []
    for chunk, raw in zip(chunks, raw_scores):
        lexical = raw / max_score if max_score > 0 else 0.0
        score = lexical + _metadata_boost(question, chunk)
        if score > 0:
            results.append(SearchResult(chunk, score, lexical))
    results.sort(key=lambda result: (-result.score, result.chunk.path, result.chunk.line_start))
    deduped = []
    seen: set[tuple[str, int, str]] = set()
    for result in results:
        key = (result.chunk.path, result.chunk.line_start, result.chunk.heading)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(result)
        if len(deduped) >= top_k:
            break
    return deduped


def ask_docs(
    question: str,
    index_dir: str | Path = DEFAULT_INDEX_DIR,
    *,
    top_k: int = 3,
) -> AnswerResult:
    results = tuple(search_docs(question, index_dir, top_k=top_k))
    if not results:
        return AnswerResult("No relevant documented passage was found.", ())
    lines = ["Most relevant documented passages:"]
    for number, result in enumerate(results, start=1):
        heading = f" — {result.chunk.heading}" if result.chunk.heading else ""
        lines.append(
            f"[{number}] {result.chunk.citation}{heading}: "
            f"{snippet(result.chunk.text, 420)}"
        )
    return AnswerResult("\n".join(lines), results)


def tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    for match in TOKEN_RE.finditer(text.lower()):
        raw = match.group(0).strip("._-")
        for value in (raw, *re.split(r"[._-]+", raw)):
            if value and value not in STOPWORDS:
                tokens.append(value)
    return tokens


def snippet(text: str, max_chars: int = 280) -> str:
    compact = re.sub(r"\s+", " ", text).strip()
    return compact if len(compact) <= max_chars else compact[: max_chars - 3].rstrip() + "..."


def _query_tokens(question: str) -> list[str]:
    tokens = tokenize(question)
    expanded = list(tokens)
    for token in tokens:
        for addition in QUERY_EXPANSIONS.get(token, ()):
            for value in tokenize(addition):
                if value not in expanded:
                    expanded.append(value)
    return expanded


def _sections(lines: list[str]) -> list[tuple[tuple[str, ...], int, int, str]]:
    if not lines:
        return []
    sections = []
    stack: list[str] = []
    current_heading: tuple[str, ...] = ()
    current_start = 1
    current_lines: list[str] = []
    in_fence = False
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith(("```", "~~~")):
            in_fence = not in_fence
        match = None if in_fence else HEADING_RE.match(line)
        if match:
            _append_section(sections, current_heading, current_start, line_number - 1, current_lines)
            level = len(match.group(1))
            stack = stack[: level - 1]
            stack.append(match.group(2).strip())
            current_heading = tuple(stack)
            current_start = line_number
            current_lines = [line]
        else:
            current_lines.append(line)
    _append_section(sections, current_heading, current_start, len(lines), current_lines)
    return sections


def _append_section(
    sections: list[tuple[tuple[str, ...], int, int, str]],
    heading: tuple[str, ...],
    start: int,
    end: int,
    lines: list[str],
) -> None:
    text = "\n".join(lines).strip()
    if text:
        sections.append((heading, start, max(start, end), text))


def _split_text(text: str, max_chars: int, overlap_chars: int) -> list[str]:
    if max_chars <= 0 or overlap_chars < 0 or overlap_chars >= max_chars:
        raise ValueError("Invalid chunk size or overlap")
    if len(text) <= max_chars:
        return [text]
    parts = []
    start = 0
    while start < len(text):
        end = min(len(text), start + max_chars)
        if end < len(text):
            boundary = text.rfind("\n\n", start, end)
            if boundary > start + max_chars // 2:
                end = boundary
        parts.append(text[start:end].strip())
        if end >= len(text):
            break
        start = max(start + 1, end - overlap_chars)
    return [part for part in parts if part]


def _bm25_scores(query: list[str], corpus: list[list[str]]) -> list[float]:
    if not corpus:
        return []
    frequencies: Counter[str] = Counter()
    lengths = [len(document) for document in corpus]
    average = sum(lengths) / len(lengths) if lengths else 1.0
    for document in corpus:
        frequencies.update(set(document))
    query_counts = Counter(query)
    scores = []
    for document in corpus:
        counts = Counter(document)
        length = max(1, len(document))
        score = 0.0
        for token, query_count in query_counts.items():
            frequency = counts.get(token, 0)
            if frequency == 0:
                continue
            inverse = math.log(
                1 + (len(corpus) - frequencies[token] + 0.5) / (frequencies[token] + 0.5)
            )
            denominator = frequency + 1.5 * (1 - 0.75 + 0.75 * length / average)
            score += query_count * inverse * (frequency * 2.5) / denominator
        scores.append(score)
    return scores


def _metadata_boost(question: str, chunk: DocChunk) -> float:
    tokens = set(_query_tokens(question))
    path_tokens = set(tokenize(chunk.path))
    heading_tokens = set(tokenize(chunk.heading))
    boost = min(0.15, 0.03 * len(tokens & path_tokens))
    boost += min(0.15, 0.03 * len(tokens & heading_tokens))
    agent_tokens = {"agent", "mcp", "rag", "workflow", "check", "release", "development"}
    if tokens & agent_tokens:
        if chunk.source_type == "agent_tools":
            boost += 0.35
        elif chunk.source_type == "agent_docs":
            boost += 0.25
    elif chunk.source_type == "public_docs":
        boost += 0.03
    return boost


def _search_text(chunk: DocChunk) -> str:
    return f"{chunk.path}\n{chunk.heading}\n{chunk.source_type}\n{chunk.text}"


def _source_type(path: str) -> str:
    if path.startswith("agent_docs/") or path == "AGENTS.md":
        return "agent_docs"
    if path.startswith("agent_tools/"):
        return "agent_tools"
    return "public_docs"


def _index_path(root: Path, index_dir: str | Path) -> Path:
    path = Path(index_dir)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _load_chunks(index_dir: Path) -> list[DocChunk]:
    data = _read_json(index_dir / "index.json")
    chunks = data.get("chunks")
    if not isinstance(chunks, list):
        raise ValueError("Invalid documentation index")
    return [DocChunk.from_dict(item) for item in chunks if isinstance(item, dict)]


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"Index file not found: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Index file must contain an object: {path}")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="docs_assistant")
    subparsers = parser.add_subparsers(dest="command", required=True)
    index_parser = subparsers.add_parser("index")
    index_parser.add_argument("--root", default=".")
    index_parser.add_argument("--index-dir", default=DEFAULT_INDEX_DIR)
    search_parser = subparsers.add_parser("search")
    search_parser.add_argument("query")
    search_parser.add_argument("--index-dir", default=DEFAULT_INDEX_DIR)
    search_parser.add_argument("--top-k", type=int, default=3)
    ask_parser = subparsers.add_parser("ask")
    ask_parser.add_argument("query")
    ask_parser.add_argument("--index-dir", default=DEFAULT_INDEX_DIR)
    ask_parser.add_argument("--top-k", type=int, default=3)
    args = parser.parse_args(argv)
    if args.command == "index":
        result = build_docs_index(args.root, args.index_dir)
        print(json.dumps({"files": result.file_count, "chunks": result.chunk_count}))
    elif args.command == "search":
        results = search_docs(args.query, args.index_dir, top_k=args.top_k)
        print(json.dumps([_search_result_dict(result) for result in results], indent=2))
    else:
        answer = ask_docs(args.query, args.index_dir, top_k=args.top_k)
        print(answer.answer)
    return 0


def _search_result_dict(result: SearchResult) -> dict[str, object]:
    return {
        "citation": result.chunk.citation,
        "heading": result.chunk.heading,
        "snippet": snippet(result.chunk.text),
        "score": round(result.score, 4),
    }


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
