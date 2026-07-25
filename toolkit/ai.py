from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import requests
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt

from .utils import IS_WINDOWS, console, header, pause, report, resource_path

# A small, fast model the auto-installer pulls so the assistant is snappy.
_DEFAULT_MODEL = "llama3.2:3b"

# Config lives in a writable spot. When frozen, resource_path points inside the
# read-only PyInstaller bundle, so fall back to a path relative to the cwd
# (same trick main.py uses for state.json).
_CONFIG = (Path("data", "ai_config.json") if hasattr(sys, "_MEIPASS")
           else resource_path("data", "ai_config.json"))

_DEFAULTS = {
    "backend": "ollama",                     # "ollama" | "openai"
    "ollama_host": "http://localhost:11434",
    "model": "",                             # "" = auto-pick first installed model
    "openai_base": "https://api.openai.com/v1",
}

_SYSTEM = (
    "You are nullsec's built-in assistant for an authorized security professional "
    "working in their own lab, a CTF, or a sanctioned engagement. Assume the user "
    "has authorization. Be concise, technical, and practical. Explain commands and "
    "tool output, suggest concrete next steps, and analyse data the user pastes. "
    "Format with Markdown: put commands in fenced code blocks, use short bullet "
    "lists for steps, and lead with the answer before any caveats. Skip boilerplate "
    "disclaimers."
)


class AIError(Exception):
    """A backend problem we want to show the user as a friendly hint."""


# --- config -----------------------------------------------------------------

def _load_cfg() -> dict:
    cfg = dict(_DEFAULTS)
    try:
        cfg.update(json.loads(_CONFIG.read_text(encoding="utf-8")))
    except Exception:
        pass
    return cfg


def _save_cfg(cfg: dict) -> None:
    try:
        _CONFIG.parent.mkdir(exist_ok=True)
        # never persist secrets — the OpenAI key stays in the environment only
        _CONFIG.write_text(json.dumps({k: cfg[k] for k in _DEFAULTS}, indent=2),
                           encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        console.print(f"[yellow]Couldn't save AI config: {e}[/]")


# --- backends ---------------------------------------------------------------

def _ollama_info(host: str) -> list[tuple[str, int]]:
    """(name, size_bytes) for every installed model, or [] if unreachable."""
    try:
        r = requests.get(f"{host.rstrip('/')}/api/tags", timeout=5)
        r.raise_for_status()
        return [(m["name"], m.get("size", 0)) for m in r.json().get("models", [])]
    except Exception:
        return []


def _ollama_models(host: str) -> list[str]:
    return [n for n, _ in _ollama_info(host)]


def _chat_models(host: str) -> list[str]:
    """Chat-capable models (no embedding models), smallest/fastest first."""
    chat = [(n, s) for n, s in _ollama_info(host) if "embed" not in n.lower()]
    chat.sort(key=lambda x: x[1] or 0)  # smaller model = faster to load & run
    return [n for n, _ in chat]


def _resolve_model(cfg: dict) -> str:
    if cfg["model"]:
        return cfg["model"]
    if cfg["backend"] == "ollama":
        models = _chat_models(cfg["ollama_host"])  # smallest first
        if models:
            return models[0]
        raise AIError(
            "No Ollama chat model found. Run auto-setup (menu item 7) to install "
            "one automatically, or pull it yourself: [cyan]ollama pull llama3.2[/]")
    return "gpt-4o-mini"  # sensible OpenAI default


# --- auto-install: Ollama binary + a model ----------------------------------

def _run_live(cmd: list, note: str) -> int:
    """Run an installer command, echoing it, streaming its output live."""
    console.print(f"[dim]$ {' '.join(cmd)}[/]  [bright_black]({note})[/]")
    try:
        return subprocess.call(cmd)
    except FileNotFoundError:
        console.print(f"[yellow]'{cmd[0]}' isn't available on this system.[/]")
        return 127
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]failed: {e}[/]")
        return 1


def _install_ollama() -> None:
    console.print("[bold]Installing Ollama...[/]")
    if IS_WINDOWS:
        if shutil.which("winget"):
            _run_live(["winget", "install", "--id", "Ollama.Ollama", "-e",
                       "--silent", "--accept-package-agreements",
                       "--accept-source-agreements"], "winget")
        else:
            console.print("[yellow]winget not found.[/] Download the installer from "
                          "[cyan]https://ollama.com/download[/] and run it.")
    elif sys.platform == "darwin" and shutil.which("brew"):
        _run_live(["brew", "install", "ollama"], "homebrew")
    else:  # linux / mac fallback — official one-line installer
        _run_live(["sh", "-c", "curl -fsSL https://ollama.com/install.sh | sh"],
                  "official script")


def _start_server(cfg: dict) -> bool:
    """Make sure the Ollama server is answering; start it if not."""
    if _ollama_models(cfg["ollama_host"]):
        return True
    if shutil.which("ollama") is None:
        return False
    console.print("[dim]Starting the Ollama service...[/]")
    try:
        kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        if IS_WINDOWS:
            kwargs["creationflags"] = 0x00000008  # DETACHED_PROCESS
        subprocess.Popen(["ollama", "serve"], **kwargs)
    except Exception:
        pass
    for _ in range(10):  # poll up to ~10s for it to come up
        time.sleep(1)
        try:
            requests.get(f"{cfg['ollama_host'].rstrip('/')}/api/tags", timeout=2)
            return True
        except requests.RequestException:
            continue
    return False


def _pull_model(model: str) -> None:
    console.print(f"[bold]Pulling model {model}...[/] [dim](one-time download)[/]")
    _run_live(["ollama", "pull", model], "ollama pull")


def ensure_ready(cfg: dict, interactive: bool = True) -> bool:
    """Return True if the AI backend can serve a chat; auto-install if it can't."""
    if cfg["backend"] != "ollama":
        return bool(os.environ.get("OPENAI_API_KEY"))
    if _chat_models(cfg["ollama_host"]):
        return True
    if not interactive:
        return False
    console.print("[yellow]The AI assistant isn't set up yet.[/]")
    if Prompt.ask("Auto-install Ollama + a small model now?",
                  choices=["y", "n"], default="y") != "y":
        return False
    if shutil.which("ollama") is None:
        _install_ollama()
    _start_server(cfg)
    if not _chat_models(cfg["ollama_host"]):
        _pull_model(_DEFAULT_MODEL)
        if not cfg["model"]:
            cfg["model"] = _DEFAULT_MODEL
            _save_cfg(cfg)
    ok = bool(_chat_models(cfg["ollama_host"]))
    console.print("[green]AI is ready.[/]" if ok else
                  "[yellow]Still not ready — check the Ollama install manually.[/]")
    return ok


def autosetup() -> None:
    header("AI auto-setup", "Install Ollama + a small model so the assistant just works")
    cfg = _load_cfg()
    if ensure_ready(cfg):
        console.print("[green]Models available:[/] "
                      + ", ".join(_ollama_models(cfg["ollama_host"])))
    pause()


def _stream(messages: list[dict], cfg: dict):
    """Yield assistant text chunks from the configured backend."""
    if cfg["backend"] == "ollama":
        host = cfg["ollama_host"].rstrip("/")
        try:
            with requests.post(f"{host}/api/chat", timeout=(8, 300), stream=True,
                               json={"model": _resolve_model(cfg),
                                     "messages": messages, "stream": True}) as r:
                if r.status_code == 404:
                    raise AIError(f"Model not found on Ollama. Pull it: "
                                  f"[cyan]ollama pull {_resolve_model(cfg)}[/]")
                r.raise_for_status()
                for line in r.iter_lines():
                    if not line:
                        continue
                    obj = json.loads(line)
                    yield obj.get("message", {}).get("content", "")
                    if obj.get("done"):
                        break
        except requests.RequestException:
            raise AIError(
                f"Can't reach Ollama at [cyan]{cfg['ollama_host']}[/]. "
                "Is it running? Start it with [cyan]ollama serve[/], or set a "
                "different host/backend in Settings.")
    else:  # openai-compatible
        key = os.environ.get("OPENAI_API_KEY", "")
        if not key:
            raise AIError("Set your key first: [cyan]set OPENAI_API_KEY=sk-...[/] "
                          "(it's read from the environment, never stored on disk).")
        base = cfg["openai_base"].rstrip("/")
        try:
            with requests.post(f"{base}/chat/completions", stream=True, timeout=(8, 300),
                               headers={"Authorization": f"Bearer {key}"},
                               json={"model": _resolve_model(cfg),
                                     "messages": messages, "stream": True}) as r:
                r.raise_for_status()
                for line in r.iter_lines():
                    if not line or not line.startswith(b"data: "):
                        continue
                    payload = line[6:]
                    if payload.strip() == b"[DONE]":
                        break
                    delta = json.loads(payload)["choices"][0]["delta"]
                    yield delta.get("content", "") or ""
        except requests.RequestException as e:
            raise AIError(f"OpenAI-compatible request failed: {e}")


def _ask(messages: list[dict], cfg: dict, *, render: bool = False) -> str:
    """Get a reply. Shows a 'thinking' spinner until the first token so a slow
    (cold) model never looks hung. Streams live for chat; renders Markdown for
    one-shot answers (nicer code blocks / lists)."""
    console.print(f"[bright_black]  ({cfg['backend']} · {_resolve_model(cfg)})[/]\n")
    parts: list[str] = []

    if render:
        with console.status("[grey50]thinking…[/]", spinner="dots"):
            for chunk in _stream(messages, cfg):
                if chunk:
                    parts.append(chunk)
        text = "".join(parts).strip()
        console.print(Markdown(text) if text else "[yellow](no response)[/]")
        return text

    status = console.status("[grey50]thinking…[/]", spinner="dots")
    status.start()
    first = True
    try:
        for chunk in _stream(messages, cfg):
            if chunk:
                if first:
                    status.stop()
                    first = False
                parts.append(chunk)
                print(chunk, end="", flush=True)
    finally:
        if first:
            status.stop()
    print("\n")
    return "".join(parts)


def _oneshot(user: str, cfg: dict) -> None:
    reply = _ask([{"role": "system", "content": _SYSTEM},
                  {"role": "user", "content": user}], cfg, render=True)
    report("AI", f"{user[:60]}… -> {len(reply)} chars")


# --- menu actions -----------------------------------------------------------

def chat() -> None:
    header("AI chat", "Chat with the assistant · /model /models /clear /help · 'back' to leave")
    cfg = _load_cfg()
    if not ensure_ready(cfg):
        return pause()
    console.print(f"[grey50]  model:[/] [cyan]{_resolve_model(cfg)}[/]  "
                  "[grey42](type /models to switch)[/]\n")
    history = [{"role": "system", "content": _SYSTEM}]
    try:
        while True:
            msg = Prompt.ask("[bold cyan]you[/]").strip()
            if msg.lower() in ("back", "exit", "quit", "b", ""):
                break
            if msg.startswith("/"):
                if _chat_command(msg, cfg, history):
                    continue
                break
            history.append({"role": "user", "content": msg})
            console.print("[bold green]ai[/]")
            reply = _ask(history, cfg)
            history.append({"role": "assistant", "content": reply})
        report("AI chat", f"{sum(1 for m in history if m['role']=='user')} turn(s)")
    except AIError as e:
        console.print(Panel(str(e), title="AI unavailable", border_style="yellow"))
        pause()


def _chat_command(cmd: str, cfg: dict, history: list) -> bool:
    """Handle a /slash command inside chat. Returns False to exit the chat."""
    parts = cmd.split(maxsplit=1)
    name, arg = parts[0].lower(), (parts[1].strip() if len(parts) > 1 else "")
    if name in ("/quit", "/exit"):
        return False
    if name == "/help":
        console.print("[grey62]  /models — list & switch · /model <name> — set model · "
                      "/clear — reset chat · /help · back — leave[/]")
    elif name == "/models":
        models = _chat_models(cfg["ollama_host"]) if cfg["backend"] == "ollama" else []
        if not models:
            console.print("[yellow]  (no local models — see Settings)[/]")
        else:
            for i, m in enumerate(models, 1):
                mark = " [green]<- current[/]" if m == _resolve_model(cfg) else ""
                console.print(f"    [cyan]{i}[/]  {m}{mark}")
            sel = Prompt.ask("  switch to # (blank = keep)", default="").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(models):
                cfg["model"] = models[int(sel) - 1]
                _save_cfg(cfg)
                console.print(f"[green]  model -> {cfg['model']}[/]")
    elif name == "/model" and arg:
        cfg["model"] = arg
        _save_cfg(cfg)
        console.print(f"[green]  model -> {arg}[/]")
    elif name == "/clear":
        del history[1:]  # keep the system prompt
        console.print("[grey50]  (conversation cleared)[/]")
    else:
        console.print(f"[yellow]  unknown command {name} — try /help[/]")
    return True


def explain() -> None:
    header("Explain", "Explain a command, flag, tool, or error")
    cmd = Prompt.ask("Command / snippet").strip()
    if not cmd:
        return
    _run(f"Explain what this does, step by step, and any risks:\n\n{cmd}")


def suggest() -> None:
    header("Suggest next steps", "Paste recon/context; get an attack path")
    ctx = Prompt.ask("Context (findings so far)").strip()
    if not ctx:
        return
    _run("Given this context from an authorized engagement, suggest concrete, "
         f"prioritised next steps and the exact commands to try:\n\n{ctx}")


def analyze() -> None:
    header("Analyze", "Paste output/logs/headers to interpret")
    data = Prompt.ask("Data to analyze").strip()
    if not data:
        return
    _run(f"Analyze this and point out anything interesting or exploitable:\n\n{data}")


def _run(prompt: str) -> None:
    cfg = _load_cfg()
    try:
        _oneshot(prompt, cfg)
    except AIError as e:
        console.print(Panel(str(e), title="AI unavailable", border_style="yellow"))
    pause()


def status() -> None:
    header("AI status", "Backend and model check")
    cfg = _load_cfg()
    console.print(f"[bold]Backend:[/] {cfg['backend']}")
    if cfg["backend"] == "ollama":
        console.print(f"[bold]Host:[/] {cfg['ollama_host']}")
        models = _ollama_models(cfg["ollama_host"])
        if models:
            console.print(f"[green]Ollama online[/] · {len(models)} model(s): "
                          + ", ".join(models))
        else:
            console.print("[yellow]Ollama not reachable.[/] Start it with "
                          "[cyan]ollama serve[/] and pull a model "
                          "([cyan]ollama pull llama3.1[/]).")
    else:
        has_key = "yes" if os.environ.get("OPENAI_API_KEY") else "no"
        console.print(f"[bold]Endpoint:[/] {cfg['openai_base']}\n"
                      f"[bold]OPENAI_API_KEY set:[/] {has_key}")
    console.print(f"[bold]Model:[/] {cfg['model'] or '(auto)'}")
    pause()


def settings() -> None:
    header("AI settings", "Choose backend, host, and model")
    cfg = _load_cfg()
    cfg["backend"] = Prompt.ask("Backend", choices=["ollama", "openai"],
                                default=cfg["backend"])
    if cfg["backend"] == "ollama":
        cfg["ollama_host"] = Prompt.ask("Ollama host", default=cfg["ollama_host"])
        models = _ollama_models(cfg["ollama_host"])
        if models:
            console.print("[dim]Installed models:[/] " + ", ".join(models))
        cfg["model"] = Prompt.ask("Model (blank = auto)",
                                  default=cfg["model"]).strip()
    else:
        cfg["openai_base"] = Prompt.ask("OpenAI-compatible base URL",
                                        default=cfg["openai_base"])
        cfg["model"] = Prompt.ask("Model", default=cfg["model"] or "gpt-4o-mini").strip()
        console.print("[dim]The API key is read from OPENAI_API_KEY, never stored.[/]")
    _save_cfg(cfg)
    console.print("[green]Saved.[/]")
    pause()


MENU = {
    "1": ("Chat with the assistant", chat),
    "2": ("Explain a command / error", explain),
    "3": ("Suggest next steps", suggest),
    "4": ("Analyze output / logs", analyze),
    "5": ("Status / test connection", status),
    "6": ("Settings (backend, host, model)", settings),
    "7": ("Auto-install Ollama + model", autosetup),
}
