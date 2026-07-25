from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, report, run_tool

# --- PDF ---------------------------------------------------------------------
# Best-effort: pull the Info-dictionary fields straight out of the raw bytes.
# Works on most non-encrypted PDFs; values inside compressed object streams need
# exiftool (option 4), which we note when we come up empty.
_PDF_FIELDS = ("Title", "Author", "Subject", "Keywords", "Creator",
               "Producer", "CreationDate", "ModDate", "Company")


def _extract_pdf(data: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    text = data.decode("latin-1", "ignore")
    for field in _PDF_FIELDS:
        # literal string:  /Author (Jane Doe)
        m = re.search(rf"/{field}\s*\(((?:[^()\\]|\\.)*)\)", text)
        if m:
            out[field] = _unescape_pdf(m.group(1))
            continue
        # hex string:  /Author <4a616e65>
        m = re.search(rf"/{field}\s*<([0-9A-Fa-f\s]+)>", text)
        if m:
            try:
                out[field] = bytes.fromhex(re.sub(r"\s", "", m.group(1))).decode(
                    "utf-16-be" if m.group(1).lower().startswith("feff") else "latin-1",
                    "ignore").lstrip("﻿")
            except ValueError:
                pass
    return out


def _unescape_pdf(s: str) -> str:
    return (s.replace("\\(", "(").replace("\\)", ")").replace("\\\\", "\\")
            .replace("\\n", " ").replace("\\r", " ").strip())


# --- Office (docx/xlsx/pptx = zip of XML) ------------------------------------
_OFFICE_TAGS = {
    "creator": "dc:creator", "lastModifiedBy": "cp:lastModifiedBy",
    "title": "dc:title", "subject": "dc:subject", "keywords": "cp:keywords",
    "revision": "cp:revision", "created": "dcterms:created",
    "modified": "dcterms:modified", "category": "cp:category",
}
_APP_TAGS = ("Application", "AppVersion", "Company", "Manager", "Template",
             "TotalTime", "Pages", "Words")


def _extract_office(data: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return out
    for part in ("docProps/core.xml", "docProps/app.xml"):
        try:
            xml = zf.read(part).decode("utf-8", "ignore")
        except KeyError:
            continue
        tags = _OFFICE_TAGS.items() if "core" in part else ((t, t) for t in _APP_TAGS)
        for label, tag in tags:
            m = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", xml, re.S)
            if m and m.group(1).strip():
                out[label] = m.group(1).strip()
    return out


def _extract(path: Path) -> tuple[str, dict[str, str]]:
    data = path.read_bytes()
    if data[:4] == b"%PDF":
        return "PDF", _extract_pdf(data)
    if data[:2] == b"PK":
        return "Office", _extract_office(data)
    return "?", {}


def _show(kind: str, meta: dict[str, str], name: str) -> None:
    if not meta:
        console.print(f"[yellow]No metadata recovered from {name}[/] "
                      "(encrypted, scrubbed, or in a compressed stream — try option 4).")
        return
    t = Table(title=f"{name}  [{kind}]", show_header=False, box=None)
    t.add_column(style="bold cyan")
    t.add_column(overflow="fold")
    for k, v in meta.items():
        t.add_row(k, v)
    console.print(t)


def harvest_file() -> None:
    header("Metadata: single file", "Extract author/software/paths from one document")
    p = Path(Prompt.ask("Document path (.pdf/.docx/.xlsx/.pptx)").strip('"'))
    if not p.is_file():
        console.print("[red]File not found.[/]")
        return pause()
    kind, meta = _extract(p)
    _show(kind, meta, p.name)
    if meta:
        report.log("osint", f"Metadata {p.name}",
                   [f"- {k}: {v}" for k, v in meta.items()])
    _scrub_note()
    pause()


# fields that expose people, software, and paths respectively
_USER_FIELDS = ("Author", "creator", "lastModifiedBy", "Manager")
_SOFTWARE_FIELDS = ("Producer", "Creator", "Application", "AppVersion")
_PATH_RE = re.compile(r"([A-Za-z]:\\[^\s\"<>|]+|\\\\[^\s\"<>|]+|file://[^\s\"<>]+)")


def harvest_folder() -> None:
    header("Metadata: folder sweep", "FOCA-style rollup: users, software, paths")
    d = Path(Prompt.ask("Folder of documents").strip('"'))
    if not d.is_dir():
        console.print("[red]Not a folder.[/]")
        return pause()
    docs = [p for p in d.rglob("*")
            if p.suffix.lower() in (".pdf", ".docx", ".xlsx", ".pptx", ".doc")]
    if not docs:
        console.print("[yellow]No documents found.[/]")
        return pause()

    users, software, paths = set(), set(), set()
    for p in docs:
        try:
            _kind, meta = _extract(p)
        except Exception:
            continue
        for f in _USER_FIELDS:
            if meta.get(f):
                users.add(meta[f])
        sw = " / ".join(meta[f] for f in _SOFTWARE_FIELDS if meta.get(f))
        if sw:
            software.add(sw)
        for v in meta.values():
            paths.update(_PATH_RE.findall(v))

    console.print(f"[dim]Scanned {len(docs)} documents.[/]\n")
    for title, items, colour in [("Usernames / people", users, "green"),
                                 ("Software & versions", software, "cyan"),
                                 ("Internal paths", paths, "yellow")]:
        console.print(f"[bold {colour}]{title}[/] ({len(items)})")
        for it in sorted(items):
            console.print(f"  {it}")
        console.print()
    report.log("osint", f"Metadata sweep {d.name}",
               [f"- {len(docs)} docs", f"- users: {', '.join(sorted(users)) or 'none'}",
                f"- software: {'; '.join(sorted(software)) or 'none'}",
                f"- paths: {', '.join(sorted(paths)) or 'none'}"])
    _scrub_note()
    pause()


def harvest_url() -> None:
    header("Metadata: from URL", "Fetch a public document and read its metadata")
    import requests
    url = Prompt.ask("Document URL").strip()
    try:
        r = requests.get(url, timeout=20, verify=False)
        r.raise_for_status()
    except Exception as e:
        console.print(f"[red]Download failed: {e}[/]")
        return pause()
    data = r.content
    if data[:4] == b"%PDF":
        kind, meta = "PDF", _extract_pdf(data)
    elif data[:2] == b"PK":
        kind, meta = "Office", _extract_office(data)
    else:
        console.print("[yellow]Not a PDF or Office document.[/]")
        return pause()
    _show(kind, meta, url.rsplit("/", 1)[-1] or url)
    if meta:
        report.log("osint", f"Metadata {url}", [f"- {k}: {v}" for k, v in meta.items()])
    _scrub_note()
    pause()


def exiftool_full() -> None:
    header("Metadata: exiftool", "Full extraction for any file type (images, media, docs)")
    p = Prompt.ask("File path").strip('"')
    # exiftool resolves natively or via WSL; translate the path if it goes to WSL
    run_tool("exiftool", [p], wsl_pathify={0})
    pause()


def doc_dorks() -> None:
    header("Document discovery dorks", "Search queries to find a target's public docs")
    domain = Prompt.ask("Target domain (e.g. example.com)")
    for ft in ("pdf", "docx", "xlsx", "pptx", "doc", "xls", "ppt", "csv"):
        console.print(f"  [green]site:{domain} filetype:{ft}[/]")
    console.print(f"  [green]site:{domain} (filetype:pdf OR filetype:docx) "
                  f"intext:confidential[/]")
    console.print("\n[dim]Download the hits, then run the folder sweep (option 2) "
                  "to roll up usernames/software/paths.[/]")
    pause()


def _scrub_note() -> None:
    console.print("[bright_black]defense: strip this before publishing — Office "
                  "'Inspect Document', `exiftool -all= file`, or `mat2`.[/]")


MENU = {
    "1": ("Extract from a file (PDF/Office)", harvest_file),
    "2": ("Folder sweep (users/software/paths)", harvest_folder),
    "3": ("Fetch a URL and extract", harvest_url),
    "4": ("Full extract via exiftool", exiftool_full),
    "5": ("Document-discovery dorks", doc_dorks),
}
