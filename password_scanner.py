#!/usr/bin/env python3
"""
secret_scanner_cli.py
A local-only, configurable secret scanner CLI for authorized use.
"""
import argparse
import os
import sys
import re
import csv
import json
import yaml
import subprocess
import math
from shutil import which
from pathlib import Path
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing

# Optional imports (used only if available)
try:
    import docx  # python-docx
except Exception:
    docx = None

try:
    from pdfminer.high_level import extract_text as pdf_extract_text
except Exception:
    pdf_extract_text = None

# Optional OCR imports
try:
    from PIL import Image
    import pytesseract
except Exception:
    Image = None
    pytesseract = None

# ---------------------------
# Defaults & helpers
# ---------------------------
DEFAULT_CONFIG = {
    "scan": {
        "depth": 3,
        "threads": max(2, multiprocessing.cpu_count() // 2),
        "max_file_size_bytes": 5_000_000,
        "exclude_dirs": [".git", "node_modules", "venv", "__pycache__"],
        "text_extensions": [".txt", ".cfg", ".conf", ".ini", ".json", ".yaml", ".yml",
                            ".env", ".py", ".sh", ".md", ".xml", ".log", ".docx", ".pdf"],
        "additional_extensions_for_text_extraction": [".docx", ".pdf"],
        "enable_ocr_for_pdf": False,
    },
    "patterns": {
        # Example patterns; users should replace/add rules in config file.
        "AWS_AccessKey": r"AKIA[0-9A-Z]{16}",
        "JWT": r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
        "Password_Assignment": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"`#;,:]{6,64})"
    },
    "output": {
        "csv": None,
        "json": None,
        "show_snippet_length": 120
    },
    "safety": {
        "require_consent": True
    }
}

def load_config(path: str = None) -> Dict[str,Any]:
    cfg = DEFAULT_CONFIG.copy()
    if not path:
        return cfg
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(p, "r", encoding="utf-8") as f:
        user_cfg = yaml.safe_load(f) or {}
    # Deep merge basic (patterns and top-level keys)
    for k, v in user_cfg.items():
        if isinstance(v, dict) and k in cfg:
            cfg[k].update(v)
        else:
            cfg[k] = v
    return cfg

def compile_patterns(patterns: Dict[str,str]) -> Dict[str,re.Pattern]:
    compiled = {}
    for name, pat in patterns.items():
        pat_str = None
        if isinstance(pat, str):
            pat_str = pat
        elif isinstance(pat, dict):
            pat_str = pat.get("regex") or pat.get("pattern")
        if not pat_str:
            continue
        try:
            compiled[name] = re.compile(pat_str)
        except re.error:
            compiled[name] = re.compile(pat_str, re.IGNORECASE)
    return compiled

def is_text_file(path: Path, text_exts: List[str]) -> bool:
    if path.suffix.lower() in [e.lower() for e in text_exts]:
        return True
    # Quick heuristic: check bytes for NULL
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
            if b"\0" in chunk:
                return False
            return True
    except Exception:
        return False

def extract_text_from_file(path: Path, config: Dict[str,Any]) -> str:
    """
    Extract text from a file. Supports plain text, .docx and .pdf.
    Uses pdftotext (poppler) if available, else pdfminer.six.
    Optionally can do OCR for image-only PDFs if `enable_ocr_for_pdf` is True in config.
    Returns empty string on failure or binary files.
    """
    # quick checks
    try:
        size = path.stat().st_size
    except Exception:
        return ""

    # respect max size
    if size > config["scan"].get("max_file_size_bytes", 5_000_000):
        return ""

    suffix = path.suffix.lower()

    # 1) If known text extension, read directly
    text_exts = [e.lower() for e in config["scan"].get("text_extensions", [])]
    if suffix in text_exts and suffix not in [".docx", ".pdf"]:
        try:
            return path.read_text(errors="ignore")
        except Exception:
            try:
                return path.read_bytes().decode("utf-8", errors="ignore")
            except Exception:
                return ""

    # 2) DOCX
    if suffix == ".docx" and docx is not None:
        try:
            doc = docx.Document(str(path))
            return "\n".join(p.text for p in doc.paragraphs if p.text)
        except Exception:
            return ""

    # 3) PDF
    if suffix == ".pdf":
        # Try pdftotext (poppler) if installed (fast + reliable)
        pdftotext_path = which("pdftotext")
        if pdftotext_path:
            try:
                out = subprocess.run([pdftotext_path, "-q", str(path), "-"], capture_output=True, timeout=30)
                if out.returncode == 0:
                    txt = out.stdout.decode("utf-8", errors="ignore")
                    if txt.strip():
                        return txt
            except Exception:
                pass

        # Fallback to pdfminer.six if available
        if pdf_extract_text is not None:
            try:
                txt = pdf_extract_text(str(path)) or ""
                if txt.strip():
                    return txt
            except Exception:
                pass

        # Optional: OCR (only if explicitly enabled in config)
        ocr_cfg = config.get("scan", {}).get("enable_ocr_for_pdf", False)
        if ocr_cfg and pytesseract is not None and Image is not None:
            try:
                pdftoppm = which("pdftoppm")
                if pdftoppm:
                    import tempfile, glob
                    with tempfile.TemporaryDirectory() as td:
                        # -png to generate PNG files
                        subprocess.run([pdftoppm, "-png", str(path), td + "/page"], check=True, timeout=60)
                        imgs = sorted(glob.glob(td + "/page*.png"))
                        pages_text = []
                        for imf in imgs:
                            img = Image.open(imf)
                            pages_text.append(pytesseract.image_to_string(img))
                        text = "\n".join(pages_text)
                        return text
                else:
                    # no pdftoppm: try a naive approach (likely won't work reliably)
                    return ""
            except Exception:
                return ""

        # nothing worked
        return ""

    # 4) Fallback: try to detect text via a simple binary check
    try:
        with open(path, "rb") as fh:
            head = fh.read(2048)
            if b"\0" in head:
                return ""
        return path.read_text(errors="ignore")
    except Exception:
        return ""

# ---------------------------
# Scanning logic
# ---------------------------
def scan_single_file(path: Path, compiled_patterns: Dict[str,re.Pattern], cfg: Dict[str,Any]) -> List[Dict[str,Any]]:
    results = []
    try:
        if not path.is_file():
            return results
        size = path.stat().st_size
        if size > cfg["scan"]["max_file_size_bytes"]:
            return results  # skip too-large
        text = extract_text_from_file(path, cfg)
        if not text:
            return results
        # normalize whitespace (helps OCR/pdf)
        text = re.sub(r'\s+', ' ', text)

        for pname, pat in compiled_patterns.items():
            for m in pat.finditer(text):
                start = max(0, m.start() - 40)
                end = min(len(text), m.end() + 40)
                snippet = text[start:end].replace("\n", " ")
                results.append({
                    "pattern": pname,
                    "match": m.group(0),
                    "file": str(path),
                    "start": m.start(),
                    "end": m.end(),
                    "snippet": snippet
                })
    except PermissionError:
        pass
    except Exception:
        # avoid crashing on weird files
        pass
    return results

def gather_files(root: Path, depth: int, exclude_dirs: List[str]) -> List[Path]:
    root = root.resolve()
    files = []
    def helper(current: Path, cur_depth: int):
        if cur_depth < 0:
            return
        try:
            for entry in current.iterdir():
                if entry.is_dir():
                    if entry.name in exclude_dirs:
                        continue
                    helper(entry, cur_depth - 1)
                elif entry.is_file():
                    files.append(entry)
        except PermissionError:
            pass
    helper(root, depth)
    return files

def scan_in_threads(files: List[Path], compiled_patterns: Dict[str,re.Pattern], cfg: Dict[str,Any]) -> List[Dict[str,Any]]:
    results = []
    max_workers = int(cfg["scan"]["threads"])
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = { ex.submit(scan_single_file, f, compiled_patterns, cfg): f for f in files }
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                results.extend(res)
    return results

# ---------------------------
# Output helpers
# ---------------------------
def save_csv(results: List[Dict[str,Any]], path: str):
    keys = ["score","pattern","match","file","start","end","snippet"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for r in results:
            row = {
                "score": r.get("score", ""),
                "pattern": r.get("pattern", ""),
                "match": r.get("match_masked", r.get("match", "")),
                "file": r.get("file", ""),
                "start": r.get("start", ""),
                "end": r.get("end", ""),
                "snippet": r.get("snippet", "")
            }
            writer.writerow(row)

def save_json(results: List[Dict[str,Any]], path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

def print_summary(results: List[Dict[str,Any]], snippet_len: int=120):
    if not results:
        print("No matches found.")
        return
    print(f"Total matches: {len(results)}\n")
    for r in results:
        snippet = (r["snippet"][:snippet_len] + "...") if len(r["snippet"]) > snippet_len else r["snippet"]
        score = r.get("score", 1)
        print(f"- [{score}] {r['pattern']} in {r['file']}")
        print(f"  match: {r['match']}")
        print(f"  snippet: {snippet}\n")

# ---------------------------
# CLI / main
# ---------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Secret scanner CLI (authorized use only).")
    p.add_argument("root", nargs="?", default=".", help="Root folder to scan (default: current dir).")
    p.add_argument("--config", "-c", help="YAML config file (overrides defaults).")
    p.add_argument("--out-csv", help="Write CSV output to this file.")
    p.add_argument("--out-json", help="Write JSON output to this file.")
    p.add_argument("--no-consent", action="store_true", help="Bypass consent prompt (use with care).")
    p.add_argument("--list-patterns", action="store_true", help="Print compiled patterns and exit.")
    return p.parse_args()

def main():
    args = parse_args()
    try:
        cfg = load_config(args.config) if args.config else DEFAULT_CONFIG
    except Exception as e:
        print("Failed loading config:", e)
        sys.exit(1)

    # allow CLI overrides for outputs
    if args.out_csv:
        cfg["output"]["csv"] = args.out_csv
    if args.out_json:
        cfg["output"]["json"] = args.out_json

    # Consent
    if cfg.get("safety", {}).get("require_consent", True) and not args.no_consent:
        print("WARNING: Only run this tool on systems & files you own or are authorized to scan.")
        consent = input("Type 'I_AM_AUTHORIZED' to continue: ").strip()
        if consent != "I_AM_AUTHORIZED":
            print("Consent not given. Exiting.")
            sys.exit(1)

    root = Path(args.root)
    if not root.exists():
        print("Root path does not exist:", root)
        sys.exit(1)

    compiled = compile_patterns(cfg.get("patterns", {}))
    if args.list_patterns:
        print("Compiled patterns:")
        for k, v in compiled.items():
            print(f"- {k}: {v.pattern}")
        sys.exit(0)

    # Gather files (respecting depth & excludes)
    files = gather_files(root, cfg["scan"]["depth"], cfg["scan"]["exclude_dirs"])
    print(f"Discovered {len(files)} files to consider (depth={cfg['scan']['depth']}).")
    # Threaded scanning

    results = scan_in_threads(files, compiled, cfg)

    # -------------------------
    # 1) Assign severity score to each result (default 1)
    # -------------------------
    severity_map = cfg.get("severity_map", {}) or {}
    for r in results:
        # guard: if score is non-int in cfg, fallback to 1
        try:
            r["score"] = int(severity_map.get(r.get("pattern"), 1))
        except Exception:
            r["score"] = 1

    # sort so highest-risk items appear first
    results = sorted(results, key=lambda x: x.get("score", 1), reverse=True)

    # -------------------------
    # 2) Post-scan dedupe & per-file limits to reduce noisy FP
    # -------------------------
    # configurable limit (can be set in config.yml under postprocessing.max_per_pattern_per_file)
    max_per_pattern_per_file = int(cfg.get("postprocessing", {}).get("max_per_pattern_per_file", 3))

    # optional stopwords from config (exact-match, case-insensitive)
    stopwords_cfg = cfg.get("postprocessing", {}).get("stopwords", []) or []
    stopwords = set([s.strip().lower() for s in stopwords_cfg if s])

    seen = set()  # (pattern, file, match) for exact dedupe
    counts_per_file_pattern = {}  # (file, pattern) -> count
    filtered_results = []

    for r in results:
        match_text = (r.get("match") or "").strip()
        # skip empty matches
        if not match_text:
            continue

        # stopwords (exact match)
        if match_text.lower() in stopwords:
            continue

        key = (r.get("pattern"), r.get("file"), match_text)
        if key in seen:
            # exact duplicate, skip
            continue

        # per-file + per-pattern counting
        fp_key = (r.get("file"), r.get("pattern"))
        cnt = counts_per_file_pattern.get(fp_key, 0)
        if cnt >= max_per_pattern_per_file:
            # skip further matches of this pattern in this file
            continue

        # accept this match
        seen.add(key)
        counts_per_file_pattern[fp_key] = cnt + 1
        filtered_results.append(r)

    # replace results with filtered_results for downstream printing/saving
    results = filtered_results

    # Print & save
    print_summary(results, snippet_len=cfg["output"].get("show_snippet_length", 120))
    if cfg["output"].get("csv"):
        save_csv(results, cfg["output"]["csv"])
        print("CSV written to", cfg["output"]["csv"])
    if cfg["output"].get("json"):
        save_json(results, cfg["output"].get("json"))
        print("JSON written to", cfg["output"].get("json"))

if __name__ == "__main__":
    main()

