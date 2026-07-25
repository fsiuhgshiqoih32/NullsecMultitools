from __future__ import annotations

import re
from pathlib import Path

from rich.prompt import Prompt
from rich.table import Table

from .utils import console, header, pause, report, resolve_tool, run_tool

METADATA = {
    "AWS": "http://169.254.169.254/latest/meta-data/  (creds: /iam/security-credentials/<role>)",
    "AWS IMDSv2": "TOKEN=$(curl -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60'); curl -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/",
    "GCP": "http://metadata.google.internal/computeMetadata/v1/  (header: Metadata-Flavor: Google)",
    "Azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01  (header: Metadata: true)",
    "DigitalOcean": "http://169.254.169.254/metadata/v1/",
    "Alibaba": "http://100.100.100.200/latest/meta-data/",
}


def _hand(binary: str, install: str) -> bool:
    if resolve_tool(binary):
        return True
    console.print(f"[yellow]{binary} not installed[/] — [cyan]{install}[/]")
    return False


def metadata_ssrf() -> None:
    header("Cloud metadata SSRF", "URLs to hit via SSRF for instance credentials")
    for prov, url in METADATA.items():
        console.print(f"[bold cyan]{prov}[/]\n  [green]{url}[/]")
    console.print("\n[bright_black]Feed these to the Web SSRF probe (5 -> 11) or a "
                  "confirmed SSRF. AWS creds come back as AccessKeyId/SecretAccessKey/Token.[/]")
    pause()


def aws_audit() -> None:
    header("AWS/multi-cloud audit", "prowler / scoutsuite security assessment")
    tool = "prowler" if resolve_tool("prowler") else ("scout" if resolve_tool("scout") else None)
    if not tool:
        console.print("[yellow]prowler/scoutsuite not installed[/] — [cyan]pip install prowler[/]")
        return pause()
    prov = Prompt.ask("Provider", choices=["aws", "azure", "gcp"], default="aws")
    if tool == "prowler":
        run_tool("prowler", [prov])
    else:
        run_tool("scout", [prov])
    pause()


def aws_exploit() -> None:
    header("AWS exploitation (Pacu)", "Post-compromise AWS enumeration & privesc")
    if not _hand("pacu", "pip install pacu"):
        return pause()
    console.print("[dim]In Pacu: import_keys --all, then run iam__enum_permissions, "
                  "iam__privesc_scan.[/]")
    run_tool("pacu", [])
    pause()


def container_scan() -> None:
    header("Container/IaC scan", "trivy — images, filesystems, IaC, secrets")
    if not _hand("trivy", "apt install trivy"):
        return pause()
    what = Prompt.ask("Scan", choices=["image", "fs", "repo"], default="image")
    target = Prompt.ask("Target (image name / path / repo)")
    run_tool("trivy", [what, target], wsl_pathify={1} if what in ("fs", "repo") else set())
    pause()


def k8s_hunt() -> None:
    header("Kubernetes recon", "kube-hunter cluster pen-test")
    if not _hand("kube-hunter", "pip install kube-hunter"):
        return pause()
    run_tool("kube-hunter", ["--remote", Prompt.ask("Cluster IP/host")])
    pause()


def dockerfile_lint() -> None:
    header("Dockerfile linter", "Flag insecure Dockerfile patterns (built-in, no deps)")
    p = Path(Prompt.ask("Dockerfile path").strip('"'))
    if not p.is_file():
        console.print("[red]File not found.[/]")
        return pause()
    findings = []
    has_user = False
    for n, raw in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        low = raw.strip().lower()
        if low.startswith("user ") and "root" not in low:
            has_user = True
        if re.search(r"^from\s+\S+:latest", low) or re.match(r"^from\s+[^:\s]+\s*$", low):
            findings.append((n, "Base image uses :latest / no tag -- pin a version"))
        if low.startswith("add ") and "http" not in low:
            findings.append((n, "ADD used for local files -- prefer COPY"))
        if "curl" in low and ("| sh" in low or "| bash" in low):
            findings.append((n, "Piping curl into a shell -- supply-chain risk"))
        if re.search(r"(password|secret|api_key|token)\s*=", low):
            findings.append((n, "Possible hardcoded secret in the build"))
        if "chmod 777" in low:
            findings.append((n, "world-writable chmod 777"))
        if low.startswith("run ") and "apt-get install" in low and "rm -rf /var/lib/apt" not in low:
            findings.append((n, "apt-get install without cleaning lists (image bloat)"))
        if "sudo " in low:
            findings.append((n, "sudo inside a container is an anti-pattern"))
    if not has_user:
        findings.append((0, "No non-root USER directive -- container runs as root"))
    if not findings:
        console.print("[green]No obvious Dockerfile issues.[/]")
        return pause()
    t = Table(title=f"{len(findings)} finding(s)")
    t.add_column("Line", justify="right", style="cyan")
    t.add_column("Issue", style="yellow")
    for n, msg in findings:
        t.add_row(str(n) if n else "-", msg)
    console.print(t)
    report.log("cloud", f"Dockerfile lint {p.name}", [f"- {len(findings)} issues"])
    pause()


def k8s_audit() -> None:
    header("K8s manifest audit", "Text-scan a Kubernetes YAML for risky settings (built-in)")
    p = Path(Prompt.ask("Manifest (.yaml) path").strip('"'))
    if not p.is_file():
        console.print("[red]File not found.[/]")
        return pause()
    low = p.read_text(encoding="utf-8", errors="ignore").lower()
    checks = [
        ("privileged: true", "Privileged container (full host access)"),
        ("hostnetwork: true", "hostNetwork shares the node's network"),
        ("hostpid: true", "hostPID shares the node's process tree"),
        ("hostipc: true", "hostIPC shares the node's IPC"),
        ("allowprivilegeescalation: true", "Privilege escalation allowed"),
        ("hostpath:", "hostPath volume mounts the node filesystem"),
        ("sys_admin", "SYS_ADMIN capability (near-root)"),
        (":latest", "Image uses :latest tag (not pinned)"),
    ]
    findings = [msg for token, msg in checks if token in low]
    if "runasnonroot: true" not in low:
        findings.append("No runAsNonRoot: true (may run as root)")
    if "limits:" not in low:
        findings.append("No resource limits (noisy-neighbour / DoS risk)")
    if not findings:
        console.print("[green]No obvious risky settings found.[/]")
        return pause()
    for f in findings:
        console.print(f"[yellow][!] {f}[/]")
    console.print("\n[dim]Heuristic text scan; for depth use trivy / kubeaudit / kube-bench.[/]")
    report.log("cloud", f"K8s audit {p.name}", [f"- {len(findings)} risky settings"])
    pause()


# ---------------------------------------------------------------------------
# Azure exploitation guide
# ---------------------------------------------------------------------------
def azure_exploit() -> None:
    header("Azure Exploitation Guide")
    console.print("Azure cloud attack methodology for authorized testing.\n")
    attacks = [
        ("Entra ID (AzureAD)", "Token theft, consent phishing, service principal abuse"),
        ("Storage accounts", "Public blob/container enumeration, SAS token abuse"),
        ("Key Vault", "Read secrets via over-permissioned managed identity"),
        ("VM", "Run command injection, custom script extension abuse"),
        ("ARM templates", "Deploy malicious resources, privilege escalation via role assignment"),
        ("Tools", "ROADtools, AADInternals, MicroBurst, Stormspotter, AzureHound"),
    ]
    for label, desc in attacks:
        console.print(f"  [cyan]{label}[/] — {desc}")
    report("Azure exploit", f"{len(attacks)} techniques")
    pause()


# ---------------------------------------------------------------------------
# Cloud enumeration guide
# ---------------------------------------------------------------------------
def cloud_enum_guide() -> None:
    header("Cloud Enumeration Guide")
    console.print("Enumerate cloud resources for authorized testing.\n")
    techniques = [
        ("AWS S3", "Bucket enumeration via permute, common names, DNS records"),
        ("Azure Blob", "Account name guessing, container enumeration"),
        ("GCP", "Cloud storage bucket enumeration, service account key leak"),
        ("GitHub", "Search for leaked cloud keys (AWS_SECRET_ACCESS_KEY, etc.)"),
        ("DNS", "CNAME records pointing to cloud services (subdomain takeover)"),
        ("Tools", "cloud_enum, bucket_finder, gcs_bucket_brute, trufflehog"),
    ]
    for label, desc in techniques:
        console.print(f"  [cyan]{label}[/] — {desc}")
    report("Cloud enum guide", f"{len(techniques)} techniques")
    pause()


# ---------------------------------------------------------------------------
# VMware exploit guide
# ---------------------------------------------------------------------------
def vmware_exploit() -> None:
    header("VMware Exploit Guide")
    console.print("VMware hypervisor exploitation for authorized testing.\n")
    attacks = [
        ("CVE-2024-37085", "ESXi auth bypass via DCUI domain group"),
        ("CVE-2023-34051", "Log4Shell variant in vCenter (RCE)"),
        ("OpenSLP", "ESXi OpenSLP RCE (CVE-2021-21974) — ransomware vector"),
        ("vCenter", "VAMI port 5480 vulnerabilities, SSO token theft"),
        ("ESXi Shell", "Enable SSH via DCUI, default root password"),
        ("Tools", "nmap vmware NSE, Metasploit vmware modules, VAST"),
    ]
    for label, desc in attacks:
        console.print(f"  [cyan]{label}[/] — {desc}")
    report("VMware exploit", f"{len(attacks)} techniques")
    pause()


# ---------------------------------------------------------------------------
# Container escape guide
# ---------------------------------------------------------------------------
def container_escape() -> None:
    header("Container Escape Guide")
    console.print("Docker/container escape techniques for authorized testing.\n")
    techniques = [
        ("Privileged container", "--privileged → mount host filesystem"),
        ("Socket mount", "Mount /var/run/docker.sock → create privileged container"),
        ("Cap abuse", "CAP_SYS_ADMIN, CAP_DAC_READ_SEARCH → host access"),
        ("cgroup release", "cgroup v1 release_agent → host RCE"),
        ("Kernel exploit", "Dirty COW (CVE-2016-5195), Dirty Pipe (CVE-2022-0847)"),
        ("runc", "CVE-2019-5736 runc container escape"),
        ("Tools", "CDK, deepce, Bypass, container-escape-checks"),
    ]
    for label, desc in techniques:
        console.print(f"  [cyan]{label}[/] — {desc}")
    report("Container escape", f"{len(techniques)} techniques")
    pause()


MENU = {
    "1": ("Cloud metadata SSRF URLs", metadata_ssrf),
    "2": ("Cloud audit (prowler/scout)", aws_audit),
    "3": ("AWS exploitation (Pacu)", aws_exploit),
    "4": ("Container/IaC scan (trivy)", container_scan),
    "5": ("Kubernetes recon (kube-hunter)", k8s_hunt),
    "6": ("Dockerfile linter (built-in)", dockerfile_lint),
    "7": ("K8s manifest audit (built-in)", k8s_audit),
    "8": ("Azure exploitation guide", azure_exploit),
    "9": ("Cloud enumeration guide", cloud_enum_guide),
    "10": ("VMware exploit guide", vmware_exploit),
    "11": ("Container escape guide", container_escape),
}
