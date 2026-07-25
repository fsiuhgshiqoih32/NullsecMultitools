from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, report, resource_path

# Workspaces are stored as individual JSON files. When frozen, resource_path
# points inside the read-only PyInstaller bundle (deleted on exit), so write to
# a "workspaces" dir next to the exe instead, so engagements actually persist.
_WS_DIR: Path = (Path("workspaces") if hasattr(sys, "_MEIPASS")
                 else resource_path("workspaces"))


def _ws_dir() -> Path:
    """Return the workspace directory, creating it if needed."""
    _WS_DIR.mkdir(parents=True, exist_ok=True)
    return _WS_DIR


def _ws_path(name: str) -> Path:
    return _ws_dir() / f"{name}.json"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class WorkspaceNote:
    when: str
    text: str


@dataclass
class WorkspaceFinding:
    category: str
    title: str
    lines: list[str]
    when: str


@dataclass
class Workspace:
    """A named engagement workspace that persists findings, notes, and metadata.

    When active, the shared ``SessionReport`` forwards every ``log()`` call into
    the workspace's ``findings`` list so nothing is lost between sessions.
    """
    name: str
    created: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    target: str = ""
    operator: str = ""
    notes: list[WorkspaceNote] = field(default_factory=list)
    findings: list[WorkspaceFinding] = field(default_factory=list)

    # -- persistence ---------------------------------------------------------

    def save(self) -> Path:
        path = _ws_path(self.name)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "name": self.name,
            "created": self.created,
            "target": self.target,
            "operator": self.operator,
            "notes": [{"when": n.when, "text": n.text} for n in self.notes],
            "findings": [
                {"category": f.category, "title": f.title,
                 "lines": f.lines, "when": f.when}
                for f in self.findings
            ],
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    @classmethod
    def load(cls, name: str) -> Workspace | None:
        path = _ws_path(name)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        ws = cls(
            name=data.get("name", name),
            created=data.get("created", datetime.now().isoformat(timespec="seconds")),
            target=data.get("target", ""),
            operator=data.get("operator", ""),
        )
        ws.notes = [WorkspaceNote(n["when"], n["text"])
                    for n in data.get("notes", [])]
        ws.findings = [WorkspaceFinding(f["category"], f["title"],
                                        f["lines"], f["when"])
                       for f in data.get("findings", [])]
        return ws

    def delete(self) -> bool:
        path = _ws_path(self.name)
        if path.is_file():
            path.unlink()
            return True
        return False

    # -- content helpers -----------------------------------------------------

    def add_note(self, text: str) -> None:
        self.notes.append(WorkspaceNote(
            datetime.now().strftime("%H:%M:%S"), text))

    def add_finding(self, category: str, title: str,
                    lines: list[str], when: str) -> None:
        self.findings.append(WorkspaceFinding(
            category, title, [str(x) for x in lines], when))

    # -- export --------------------------------------------------------------

    def as_markdown(self) -> str:
        out = [
            f"# Engagement: {self.name}",
            f"\n_Created {self.created} · "
            f"{len(self.findings)} finding(s) · "
            f"{len(self.notes)} note(s)_\n",
        ]
        if self.target:
            out.append(f"**Target:** {self.target}\n")
        if self.operator:
            out.append(f"**Operator:** {self.operator}\n")
        if self.findings:
            out.append("## Findings\n")
            for f in self.findings:
                out.append(f"### [{f.category}] {f.title}  \n_{f.when}_\n")
                out.extend(f.lines)
                out.append("")
        if self.notes:
            out.append("## Notes\n")
            for n in self.notes:
                out.append(f"- _{n.when}_ — {n.text}")
            out.append("")
        return "\n".join(out)

    def save_markdown(self, directory: str | Path = ".") -> Path:
        name = f"workspace_{self.name}_{datetime.now():%Y%m%d_%H%M%S}.md"
        path = Path(directory) / name
        path.write_text(self.as_markdown(), encoding="utf-8")
        return path

    def save_html(self, directory: str | Path = ".") -> Path:
        findings_html = []
        for f in self.findings:
            body = "<br>".join(x.replace("`", "") for x in f.lines)
            findings_html.append(
                f'<div class="card"><span class="cat">{f.category}</span>'
                f'<span class="time">{f.when}</span><h3>{f.title}</h3>'
                f'<pre>{body}</pre></div>')
        notes_html = "".join(
            f'<div class="note"><span class="time">{n.when}</span>{n.text}</div>'
            for n in self.notes)
        html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>workspace: {self.name}</title><style>
body{{background:#0d1117;color:#c9d1d9;font-family:Segoe UI,system-ui,sans-serif;margin:0;padding:2rem}}
h1{{color:#39d353;font-family:monospace;letter-spacing:2px}}
.meta{{color:#8b949e;margin-bottom:1.5rem}}
.card{{background:#161b22;border:1px solid #30363d;border-left:3px solid #39d353;border-radius:6px;padding:1rem 1.2rem;margin:.8rem 0}}
.note{{background:#161b22;border:1px solid #30363d;border-left:3px solid #d29922;border-radius:6px;padding:.6rem 1.2rem;margin:.4rem 0}}
.cat{{background:#1f6feb;color:#fff;border-radius:4px;padding:1px 8px;font-size:.75rem;text-transform:uppercase}}
.time{{color:#8b949e;float:right;font-family:monospace}}
h3{{margin:.5rem 0}}pre{{color:#8b949e;white-space:pre-wrap;margin:0}}
h2{{color:#8b949e;border-bottom:1px solid #30363d;padding-bottom:.3rem}}
</style></head><body>
<h1>&#9608; ENGAGEMENT: {self.name}</h1>
<div class="meta">Created {self.created} &middot; {len(self.findings)} finding(s) &middot; {len(self.notes)} note(s)
{'<br>Target: ' + self.target if self.target else ''}
{'<br>Operator: ' + self.operator if self.operator else ''}</div>
<h2>Findings</h2>
{''.join(findings_html) or '<p>No findings.</p>'}
<h2>Notes</h2>
{''.join(notes_html) or '<p>No notes.</p>'}
</body></html>"""
        name = f"workspace_{self.name}_{datetime.now():%Y%m%d_%H%M%S}.html"
        path = Path(directory) / name
        path.write_text(html, encoding="utf-8")
        return path


# ---------------------------------------------------------------------------
# Active workspace singleton
# ---------------------------------------------------------------------------

_active: Workspace | None = None


def get_active() -> Workspace | None:
    return _active


def set_active(ws: Workspace | None) -> None:
    global _active
    _active = ws
    # Wire the workspace into the session reporter so findings auto-persist.
    report.active_workspace = ws


def is_active() -> bool:
    return _active is not None


def _list_workspaces() -> list[str]:
    d = _ws_dir()
    return sorted(p.stem for p in d.glob("*.json"))


# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------

def create_workspace() -> None:
    header("Create workspace", "Start a new named engagement")
    name = Prompt.ask("Workspace name").strip()
    if not name:
        console.print("[yellow]Name cannot be empty.[/]")
        return pause()
    if _ws_path(name).is_file():
        overwrite = Prompt.ask(
            f"Workspace '{name}' already exists. Overwrite?",
            choices=["y", "n"], default="n")
        if overwrite != "y":
            console.print("[yellow]Cancelled.[/]")
            return pause()
    target = Prompt.ask("Target (optional)", default="")
    operator = Prompt.ask("Operator (optional)", default="")
    ws = Workspace(name=name, target=target, operator=operator)
    ws.save()
    set_active(ws)
    console.print(f"\n[green]Created and activated workspace:[/] [bold]{name}[/]")
    report.log("workspace", f"Created workspace '{name}'",
               [f"- Target: {target or '(none)'}",
                f"- Operator: {operator or '(none)'}"])
    pause()


def load_workspace() -> None:
    header("Load workspace", "Open an existing engagement")
    names = _list_workspaces()
    if not names:
        console.print("[yellow]No saved workspaces found.[/]")
        return pause()
    tbl = Table(title="Saved workspaces", show_header=False, box=None)
    tbl.add_column(style="bold cyan")
    tbl.add_column()
    for i, n in enumerate(names, 1):
        tbl.add_row(str(i), n)
    console.print(tbl)
    choice = Prompt.ask("Select (number or name)", default="1").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(names):
        name = names[int(choice) - 1]
    elif choice in names:
        name = choice
    else:
        console.print("[red]Invalid selection.[/]")
        return pause()
    ws = Workspace.load(name)
    if ws is None:
        console.print(f"[red]Failed to load workspace '{name}'.[/]")
        return pause()
    set_active(ws)
    console.print(f"\n[green]Loaded workspace:[/] [bold]{name}[/]")
    console.print(f"  [dim]{len(ws.findings)} finding(s) · "
                  f"{len(ws.notes)} note(s)[/]")
    pause()


def list_workspaces() -> None:
    header("Workspaces", "All saved engagements")
    names = _list_workspaces()
    if not names:
        console.print("[yellow]No saved workspaces.[/]")
        return pause()
    tbl = Table(title=f"{len(names)} workspace(s)")
    tbl.add_column("Name", style="bold cyan")
    tbl.add_column("Created", style="dim")
    tbl.add_column("Target")
    tbl.add_column("Findings", justify="right")
    tbl.add_column("Notes", justify="right")
    tbl.add_column("Active")
    for n in names:
        ws = Workspace.load(n)
        if ws is None:
            continue
        active = "[green]yes[/]" if _active and _active.name == n else ""
        tbl.add_row(n, ws.created[:10], ws.target or "-",
                    str(len(ws.findings)), str(len(ws.notes)), active)
    console.print(tbl)
    pause()


def save_workspace() -> None:
    header("Save workspace")
    ws = get_active()
    if ws is None:
        console.print("[yellow]No active workspace. Create or load one first.[/]")
        return pause()
    path = ws.save()
    console.print(f"[green]Saved:[/] {path}")
    pause()


def workspace_info() -> None:
    header("Workspace info")
    ws = get_active()
    if ws is None:
        console.print("[yellow]No active workspace.[/]")
        return pause()
    console.print(f"  [bold]Name:[/]     {ws.name}")
    console.print(f"  [bold]Created:[/]  {ws.created}")
    console.print(f"  [bold]Target:[/]   {ws.target or '-'}")
    console.print(f"  [bold]Operator:[/] {ws.operator or '-'}")
    console.print(f"  [bold]Findings:[/] {len(ws.findings)}")
    console.print(f"  [bold]Notes:[/]    {len(ws.notes)}")
    console.print(f"  [bold]File:[/]     {_ws_path(ws.name)}")
    pause()


def add_note() -> None:
    header("Add note")
    ws = get_active()
    if ws is None:
        console.print("[yellow]No active workspace.[/]")
        return pause()
    text = Prompt.ask("Note text")
    if not text.strip():
        console.print("[yellow]Empty note, ignored.[/]")
        return pause()
    ws.add_note(text.strip())
    ws.save()
    console.print("[green]Note added and workspace saved.[/]")
    pause()


def view_notes() -> None:
    header("Workspace notes")
    ws = get_active()
    if ws is None:
        console.print("[yellow]No active workspace.[/]")
        return pause()
    if not ws.notes:
        console.print("[dim]No notes yet.[/]")
        return pause()
    for n in ws.notes:
        console.print(f"  [cyan]{n.when}[/]  {n.text}")
    pause()


def view_findings() -> None:
    header("Workspace findings")
    ws = get_active()
    if ws is None:
        console.print("[yellow]No active workspace.[/]")
        return pause()
    if not ws.findings:
        console.print("[dim]No findings recorded yet.[/]")
        return pause()
    tbl = Table(title=f"{len(ws.findings)} finding(s) in '{ws.name}'")
    tbl.add_column("#", justify="right", style="dim")
    tbl.add_column("Time", style="cyan")
    tbl.add_column("Category", style="magenta")
    tbl.add_column("Title")
    for i, f in enumerate(ws.findings, 1):
        tbl.add_row(str(i), f.when, f.category, f.title)
    console.print(tbl)
    pause()


def import_session() -> None:
    header("Import session report into workspace")
    ws = get_active()
    if ws is None:
        console.print("[yellow]No active workspace.[/]")
        return pause()
    if not report.entries:
        console.print("[yellow]Session report is empty.[/]")
        return pause()
    before = len(ws.findings)
    for e in report.entries:
        ws.add_finding(e.category, e.title, e.lines, e.when)
    ws.save()
    added = len(ws.findings) - before
    console.print(f"[green]Imported {added} finding(s) from session report.[/]")
    pause()


def export_workspace() -> None:
    header("Export workspace report")
    ws = get_active()
    if ws is None:
        console.print("[yellow]No active workspace.[/]")
        return pause()
    choice = Prompt.ask("Export as [m]arkdown, [h]tml, or [b]ack",
                        choices=["m", "h", "b"], default="m")
    if choice == "m":
        path = ws.save_markdown()
        console.print(f"[green]Saved:[/] {path}")
    elif choice == "h":
        path = ws.save_html()
        console.print(f"[green]Saved:[/] {path}")
    pause()


def delete_workspace() -> None:
    header("Delete workspace")
    names = _list_workspaces()
    if not names:
        console.print("[yellow]No saved workspaces.[/]")
        return pause()
    for i, n in enumerate(names, 1):
        marker = " [green](active)[/]" if _active and _active.name == n else ""
        console.print(f"  [cyan]{i}[/]  {n}{marker}")
    choice = Prompt.ask("Select (number or name)", default="1").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(names):
        name = names[int(choice) - 1]
    elif choice in names:
        name = choice
    else:
        console.print("[red]Invalid selection.[/]")
        return pause()
    confirm = Prompt.ask(f"Delete '{name}'? This cannot be undone",
                         choices=["y", "n"], default="n")
    if confirm != "y":
        console.print("[yellow]Cancelled.[/]")
        return pause()
    if _active and _active.name == name:
        set_active(None)
    ws = Workspace.load(name)
    if ws:
        ws.delete()
    console.print(f"[green]Deleted workspace '{name}'.[/]")
    pause()


def close_workspace() -> None:
    header("Close workspace")
    ws = get_active()
    if ws is None:
        console.print("[yellow]No active workspace.[/]")
        return pause()
    save = Prompt.ask("Save before closing?", choices=["y", "n"], default="y")
    if save == "y":
        ws.save()
        console.print("[green]Saved.[/]")
    set_active(None)
    console.print("[dim]Workspace closed.[/]")
    pause()


MENU = {
    "1": ("Create workspace", create_workspace),
    "2": ("Load workspace", load_workspace),
    "3": ("List workspaces", list_workspaces),
    "4": ("Workspace info", workspace_info),
    "5": ("Add note", add_note),
    "6": ("View notes", view_notes),
    "7": ("View findings", view_findings),
    "8": ("Import session report", import_session),
    "9": ("Export report (MD/HTML)", export_workspace),
    "10": ("Save workspace", save_workspace),
    "11": ("Close workspace", close_workspace),
    "12": ("Delete workspace", delete_workspace),
}
