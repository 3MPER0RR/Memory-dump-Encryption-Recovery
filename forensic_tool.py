#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║                   Memory & Encryption Recovery            ║
║                    Linux / macOS                          ║
╚═══════════════════════════════════════════════════════════╝
"""

import os
import sys
import struct
import hashlib
import subprocess
import platform
import datetime
import re
import json
import mmap
import ctypes
from pathlib import Path

# ─── Color palette ──────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"

def c(color, text): return f"{color}{text}{C.RESET}"
def header(text):   print(f"\n{C.BOLD}{C.CYAN}{'─'*60}{C.RESET}\n {C.BOLD}{C.WHITE}{text}{C.RESET}\n{C.BOLD}{C.CYAN}{'─'*60}{C.RESET}")
def ok(msg):        print(f"  {c(C.GREEN,'✔')} {msg}")
def warn(msg):      print(f"  {c(C.YELLOW,'⚠')} {msg}")
def err(msg):       print(f"  {c(C.RED,'✖')} {msg}")
def info(msg):      print(f"  {c(C.CYAN,'ℹ')} {msg}")
def ask(msg):       return input(f"\n  {c(C.MAGENTA,'▶')} {msg}: ").strip()

OS = platform.system()  # 'Linux' or 'Darwin'

# ══════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════
def banner():
    os.system("clear")
    print(f"""{C.BOLD}{C.CYAN} +-+-+-+-+-+-+ +-+ +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
 |M|e|m|o|r|y| |&| |E|n|c|r|y|p|t|i|o|n| |R|e|c|o|v|e|r|y|
 +-+-+-+-+-+-+ +-+ +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
{C.RESET}{C.DIM}     Memory & Encryption Recovery Toolkit
                        Linux / macOS
                   ⚠  For authorized use only ⚠{C.RESET}
""")
    print(f"  {c(C.DIM,'System:')} {c(C.WHITE, OS)}  |  "
          f"{c(C.DIM,'User:')} {c(C.WHITE, os.getlogin())}  |  "
          f"{c(C.DIM,'Date:')} {c(C.WHITE, datetime.datetime.now().strftime('%Y-%m-%d %H:%M'))}\n")


# ══════════════════════════════════════════════════════════════
#  MODULE 1 — MEMORY FORENSICS
# ══════════════════════════════════════════════════════════════

class MemoryForensics:

    PROC_MAPS = "/proc/{pid}/maps"
    PROC_MEM  = "/proc/{pid}/mem"

    def show_memory_overview(self):
        header("MEMORY OVERVIEW — System Snapshot")
        if OS == "Linux":
            self._linux_overview()
        elif OS == "Darwin":
            self._macos_overview()
        else:
            err("Unsupported OS"); return

    def _linux_overview(self):
        try:
            with open("/proc/meminfo") as f:
                raw = f.read()
            fields = {}
            for line in raw.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    fields[parts[0].rstrip(':')] = int(parts[1])

            total  = fields.get("MemTotal", 0)
            free   = fields.get("MemFree", 0)
            avail  = fields.get("MemAvailable", 0)
            cached = fields.get("Cached", 0) + fields.get("Buffers", 0)
            used   = total - free

            def kb(v): return f"{v//1024} MB ({v//1024//1024} GB)"

            print(f"""
  {C.BOLD}Physical RAM{C.RESET}
    Total        : {c(C.WHITE, kb(total))}
    Used         : {c(C.YELLOW, kb(used))}
    Available    : {c(C.GREEN, kb(avail))}
    Cached/Buf   : {c(C.CYAN, kb(cached))}
""")
            swap_total = fields.get("SwapTotal", 0)
            swap_free  = fields.get("SwapFree", 0)
            print(f"  {C.BOLD}Swap{C.RESET}")
            print(f"    Total        : {c(C.WHITE, kb(swap_total))}")
            print(f"    Used         : {c(C.YELLOW, kb(swap_total - swap_free))}\n")

        except PermissionError:
            warn("/proc/meminfo not readable")

        self._linux_segment_summary()

    def _linux_segment_summary(self):
        print(f"  {C.BOLD}Segment types across all processes:{C.RESET}\n")
        types = {"heap": 0, "stack": 0, "vdso": 0, "anon": 0, "file": 0, "other": 0}
        count = 0
        try:
            for pid_dir in Path("/proc").iterdir():
                if not pid_dir.name.isdigit(): continue
                maps = pid_dir / "maps"
                try:
                    for line in maps.read_text().splitlines():
                        count += 1
                        if "[heap]"  in line: types["heap"]  += 1
                        elif "[stack" in line: types["stack"] += 1
                        elif "[vdso]" in line: types["vdso"]  += 1
                        elif line.split()[-1].startswith("/"): types["file"] += 1
                        elif len(line.split()) == 5: types["anon"] += 1
                        else: types["other"] += 1
                except: pass
        except: pass

        for k,v in types.items():
            pct = int(v/max(count,1)*40)
            print(f"    {k:<8} {'█'*pct}{C.DIM}{'░'*(40-pct)}{C.RESET}  {c(C.WHITE, str(v))} regions")
        print()

    def _macos_overview(self):
        try:
            out = subprocess.check_output(["vm_stat"], text=True)
            print(f"\n  {C.BOLD}macOS vm_stat output:{C.RESET}\n")
            page = 4096
            for line in out.splitlines():
                m = re.match(r"(.+?):\s+(\d+)", line)
                if m:
                    key, val = m.group(1).strip(), int(m.group(2))
                    mb = val * page // 1024 // 1024
                    print(f"    {c(C.CYAN, key):<45} {c(C.WHITE, str(mb))} MB")
            print()
        except Exception as e:
            err(f"vm_stat error: {e}")

    def list_processes(self):
        header("RUNNING PROCESSES")
        try:
            if OS == "Linux":
                self._list_linux_processes()
            else:
                self._list_macos_processes()
        except Exception as e:
            err(f"Error: {e}")

    def _list_linux_processes(self):
        procs = []
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit(): continue
            try:
                pid = int(pid_dir.name)
                comm = (pid_dir / "comm").read_text().strip()
                status = (pid_dir / "status").read_text()
                vm_rss = 0
                for line in status.splitlines():
                    if line.startswith("VmRSS:"):
                        vm_rss = int(line.split()[1])
                procs.append((pid, comm, vm_rss))
            except: pass

        procs.sort(key=lambda x: x[2], reverse=True)
        print(f"\n  {'PID':<8} {'NAME':<25} {'RSS (MB)'}")
        print(f"  {'─'*8} {'─'*25} {'─'*10}")
        for pid, name, rss in procs[:30]:
            mb = rss // 1024
            color = C.RED if mb > 500 else C.YELLOW if mb > 100 else C.WHITE
            print(f"  {c(C.CYAN,str(pid)):<16} {name:<25} {c(color, str(mb))}")
        print(f"\n  {c(C.DIM, f'Showing top 30 of {len(procs)} processes')}")

    def _list_macos_processes(self):
        out = subprocess.check_output(["ps", "aux"], text=True).splitlines()
        print(f"\n  {c(C.BOLD, out[0])}")
        print(f"  {'─'*80}")
        for line in out[1:31]:
            print(f"  {line}")

    def dump_process(self):
        header("MEMORY DUMP — Process")
        if OS == "Linux":
            self._dump_linux()
        elif OS == "Darwin":
            self._dump_macos()

    def _dump_linux(self):
        if os.geteuid() != 0:
            warn("Root required for full memory read. Partial info available.")

        self.list_processes()
        pid_str = ask("Enter PID to dump (or 0 to cancel)")
        if pid_str == "0" or not pid_str.isdigit():
            warn("Cancelled"); return
        pid = int(pid_str)

        out_dir = Path(f"dump_pid{pid}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
        out_dir.mkdir()
        info(f"Dumping PID {pid} → {out_dir}/")

        maps_file = Path(f"/proc/{pid}/maps")
        mem_file  = Path(f"/proc/{pid}/mem")

        try:
            maps = maps_file.read_text().splitlines()
        except PermissionError:
            err("Cannot read /proc/{pid}/maps — need root"); return

        (out_dir / "maps.txt").write_text("\n".join(maps))
        ok(f"Saved maps.txt ({len(maps)} regions)")

        strings_found = []
        dump_count    = 0
        total_bytes   = 0

        try:
            mem = open(mem_file, "rb")
        except PermissionError:
            warn("Cannot read process memory (need root). Saving maps only.")
            mem = None

        for line in maps:
            parts = line.split()
            if len(parts) < 5: continue
            addr_range, perms = parts[0], parts[1]
            if "r" not in perms: continue

            try:
                start, end = [int(x, 16) for x in addr_range.split("-")]
                size = end - start
                if size > 512 * 1024 * 1024: continue
                if size == 0: continue

                if mem:
                    mem.seek(start)
                    data = mem.read(size)
                    total_bytes += len(data)
                    dump_count  += 1

                    label = parts[5].replace("/","_") if len(parts) > 5 else "anon"
                    fname = f"region_{addr_range.replace('-','_')}_{label[:20]}.bin"
                    (out_dir / fname).write_bytes(data)

                    found = re.findall(rb"[\x20-\x7e]{6,}", data)
                    strings_found.extend([s.decode("ascii","ignore") for s in found[:50]])

            except Exception:
                continue

        if mem: mem.close()

        unique_strings = list(dict.fromkeys(strings_found))[:2000]
        (out_dir / "strings.txt").write_text("\n".join(unique_strings))

        ok(f"Dumped {dump_count} regions — {total_bytes//1024//1024} MB total")
        ok(f"Extracted {len(unique_strings)} unique strings")

        self._flag_suspicious(unique_strings, out_dir)
        info(f"All output saved in: {c(C.WHITE, str(out_dir))}/")
        self._generate_report(pid, out_dir, dump_count, total_bytes, unique_strings)

    def _dump_macos(self):
        warn("macOS restricts direct memory access (SIP). Using vmmap + sample.")
        self.list_processes()
        pid_str = ask("Enter PID to analyze")
        if not pid_str.isdigit(): warn("Cancelled"); return
        pid = int(pid_str)

        out_dir = Path(f"dump_pid{pid}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
        out_dir.mkdir()

        try:
            out = subprocess.check_output(["vmmap", str(pid)], text=True, stderr=subprocess.DEVNULL)
            (out_dir / "vmmap.txt").write_text(out)
            ok("vmmap.txt saved")
        except Exception as e:
            warn(f"vmmap failed: {e}")

        info(f"Output saved in: {c(C.WHITE, str(out_dir))}/")

    def _flag_suspicious(self, strings, out_dir):
        patterns = {
            "Shell commands":   [r"(?:bash|sh|zsh|/bin/)", r"exec\(", r"system\("],
            "Network IOCs":     [r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", r"https?://", r"socket"],
            "Credentials":      [r"(?i)password[=:\s]", r"(?i)token[=:\s]", r"(?i)api.?key"],
            "Encoded data":     [r"[A-Za-z0-9+/]{40,}={0,2}"],
        }
        findings = {}
        for cat, pats in patterns.items():
            hits = []
            for s in strings:
                for p in pats:
                    if re.search(p, s):
                        hits.append(s); break
            if hits:
                findings[cat] = hits[:20]

        if findings:
            warn("Suspicious patterns found:")
            for cat, hits in findings.items():
                print(f"\n    {c(C.RED, cat)}:")
                for h in hits[:5]:
                    print(f"      {c(C.YELLOW, h[:100])}")
            (out_dir / "suspicious.txt").write_text(json.dumps(findings, indent=2))
            ok("suspicious.txt saved")
        else:
            ok("No obviously suspicious patterns detected")

    def _generate_report(self, pid, out_dir, regions, total_bytes, strings):
        report = f"""FORENSIC MEMORY DUMP REPORT
{'='*50}
Date    : {datetime.datetime.now()}
OS      : {OS}
PID     : {pid}
Output  : {out_dir}

STATISTICS
  Regions dumped : {regions}
  Total size     : {total_bytes//1024//1024} MB
  Strings found  : {len(strings)}

TOP STRINGS SAMPLE
{chr(10).join(strings[:20])}
"""
        (out_dir / "report.txt").write_text(report)
        ok("report.txt generated")

    def menu(self):
        while True:
            header("MODULE 1 — MEMORY FORENSICS")
            print(f"  {c(C.CYAN,'1')}. Memory overview (types & usage)")
            print(f"  {c(C.CYAN,'2')}. List running processes")
            print(f"  {c(C.CYAN,'3')}. Dump process memory")
            print(f"  {c(C.CYAN,'0')}. Back to main menu\n")
            ch = ask("Choose")
            if   ch == "1": self.show_memory_overview()
            elif ch == "2": self.list_processes()
            elif ch == "3": self.dump_process()
            elif ch == "0": break
            else: warn("Invalid choice")
            input(f"\n  {c(C.DIM,'Press Enter to continue...')}")


# ══════════════════════════════════════════════════════════════
#  MODULE 2 — ENCRYPTION RECOVERY
# ══════════════════════════════════════════════════════════════

MAGIC_SIGNATURES = {
    "VeraCrypt / TrueCrypt": [(0, b"\x00"*64,           "No readable header (hidden volume possible)")],
    "LUKS":                  [(0, b"LUKS\xba\xbe",       "LUKS disk encryption")],
    "ZIP (encrypted)":       [(0, b"PK\x03\x04",         "ZIP archive — check for encryption flag")],
    "7-Zip":                 [(0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive")],
    "OpenSSL enc":           [(0, b"Salted__",            "OpenSSL symmetric encryption")],
    "PDF (protected)":       [(0, b"%PDF",                "PDF — may have password protection")],
    "GPG/PGP":               [(0, b"\x85\x02",            "GPG/PGP encrypted message")],
    "GPG binary":            [(0, b"\x85\x05",            "GPG binary packet")],
    "BitLocker":             [(0, b"-FVE-FS-",            "BitLocker encrypted volume")],
    "eCryptfs":              [(0, b"ECRYPTFS",            "eCryptfs encrypted filesystem")],
    "age encryption":        [(0, b"age-encryption.org",  "age encrypted file")],
    "RAR (encrypted)":       [(0, b"Rar!\x1a\x07",        "RAR archive — may be encrypted")],
}

class CryptoRecovery:

    def identify_file(self, path: Path):
        header("ENCRYPTION IDENTIFICATION")
        info(f"Analyzing: {c(C.WHITE, str(path))}")

        try:
            data = path.read_bytes()
        except Exception as e:
            err(f"Cannot read file: {e}"); return None

        size = len(data)
        info(f"File size: {c(C.WHITE, f'{size} bytes ({size//1024} KB)')}")

        entropy = self._entropy(data)
        info(f"Shannon entropy: {c(C.YELLOW if entropy>7 else C.WHITE, f'{entropy:.4f} / 8.0')}")
        if entropy > 7.5:
            warn("Very high entropy → strongly suggests encryption or compression")
        elif entropy > 6.5:
            warn("High entropy → possible encryption or packed data")
        else:
            ok("Normal entropy — may not be encrypted")

        detected = []
        for name, checks in MAGIC_SIGNATURES.items():
            for offset, magic, note in checks:
                if data[offset:offset+len(magic)] == magic:
                    detected.append((name, note))

        if detected:
            print(f"\n  {C.BOLD}Detected format(s):{C.RESET}")
            for name, note in detected:
                print(f"    {c(C.GREEN,'✔')} {c(C.WHITE,name)}")
                print(f"       {c(C.DIM,note)}")
        else:
            warn("No known magic signature matched")
            self._heuristic_guess(data)

        if data[:2] == b"PK":
            self._check_zip_encryption(data)

        print(f"\n  {C.BOLD}First 32 bytes (hex):{C.RESET}")
        hexdump = " ".join(f"{b:02x}" for b in data[:32])
        print(f"    {c(C.CYAN, hexdump)}")

        print(f"\n  {C.BOLD}File fingerprints:{C.RESET}")
        for algo in ["md5","sha1","sha256"]:
            h = hashlib.new(algo, data).hexdigest()
            print(f"    {c(C.DIM,algo.upper()+':')} {c(C.WHITE,h)}")

        return detected

    def _entropy(self, data: bytes) -> float:
        from math import log2
        if not data: return 0.0
        freq = [0]*256
        for b in data: freq[b] += 1
        n = len(data)
        return -sum((f/n)*log2(f/n) for f in freq if f)

    def _heuristic_guess(self, data: bytes):
        printable = sum(1 for b in data[:512] if 32 <= b <= 126)
        ratio = printable / min(512, len(data))
        if ratio < 0.1:
            warn(f"Only {ratio*100:.1f}% printable chars → likely binary/encrypted")
            info("Possible types: raw AES/ChaCha20 output, encrypted disk image")
        elif ratio > 0.9:
            info("Mostly text — may be base64-encoded ciphertext or PEM key")

    def _check_zip_encryption(self, data: bytes):
        if len(data) > 8:
            flags = struct.unpack_from("<H", data, 6)[0]
            if flags & 0x1:
                warn("ZIP encryption flag is SET — file is password-protected")
                info("Encryption: Traditional ZipCrypto or AES-256 (depends on version)")
            else:
                ok("ZIP encryption flag not set — file may be unencrypted")

    def attempt_recovery(self, path: Path, detected):
        header("RECOVERY ATTEMPT")
        print(f"""
  {C.BOLD}Recovery options:{C.RESET}

  {c(C.CYAN,'1')}. Wordlist / dictionary attack
  {c(C.CYAN,'2')}. Common password patterns (dates, names, sequences)
  {c(C.CYAN,'3')}. Brute force (short passwords ≤5 chars)  {c(C.DIM,'[slow]')}
  {c(C.CYAN,'4')}. Try passwords you remember
  {c(C.CYAN,'0')}. Back
""")
        ch = ask("Choose recovery method")
        if ch == "0": return
        if   ch == "1": self._wordlist_attack(path, detected)
        elif ch == "2": self._pattern_attack(path, detected)
        elif ch == "3": self._bruteforce(path, detected)
        elif ch == "4": self._manual_try(path, detected)

    def _try_zip_password(self, path: Path, pwd: str) -> bool:
        try:
            result = subprocess.run(
                ["unzip", "-P", pwd, "-t", str(path)],
                capture_output=True, timeout=5)
            return result.returncode == 0
        except: return False

    def _try_openssl_password(self, path: Path, pwd: str) -> bool:
        try:
            result = subprocess.run(
                ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
                 "-in", str(path), "-pass", f"pass:{pwd}", "-out", "/dev/null"],
                capture_output=True, timeout=5)
            return result.returncode == 0
        except: return False

    def _get_try_fn(self, path: Path, detected):
        names = [d[0] for d in detected] if detected else []
        if "ZIP (encrypted)" in names:
            return lambda p: self._try_zip_password(path, p)
        elif "OpenSSL enc" in names:
            return lambda p: self._try_openssl_password(path, p)
        else:
            return lambda p: self._try_zip_password(path, p)

    def _run_attack(self, passwords, try_fn, label):
        total = len(passwords)
        found = None
        for i, pwd in enumerate(passwords):
            pct = (i+1)/total*100
            print(f"\r  Testing [{i+1}/{total}] {pct:5.1f}%  {c(C.DIM, pwd[:40]):<45}", end="", flush=True)
            if try_fn(pwd):
                found = pwd; break
        print()
        if found:
            print(f"\n  {C.BOLD}{C.GREEN}{'★'*50}{C.RESET}")
            print(f"  {C.BOLD}{C.GREEN}  PASSWORD FOUND: {found}{C.RESET}")
            print(f"  {C.BOLD}{C.GREEN}{'★'*50}{C.RESET}\n")
        else:
            warn(f"Password not found in {label} ({total} attempts)")
        return found

    def _wordlist_attack(self, path, detected):
        info("Wordlist attack — using built-in common passwords")
        base = [
            "password","123456","password123","admin","letmein","welcome",
            "monkey","dragon","master","sunshine","princess","shadow",
            "abc123","qwerty","football","iloveyou","login","passw0rd",
            "secret","root","toor","alpine","raspberry","changeme",
            "test","guest","default","administrator","pass","1234",
        ]
        exts = ["","1","123","!","2023","2024","2025","#","@","01"]
        wordlist = [b+e for b in base for e in exts]

        wl_path = ask("Path to custom wordlist file (Enter to skip)")
        if wl_path and Path(wl_path).exists():
            try:
                custom = Path(wl_path).read_text(errors="ignore").splitlines()
                wordlist = custom + wordlist
                info(f"Loaded {len(custom)} passwords from file")
            except: warn("Could not load wordlist file")

        try_fn = self._get_try_fn(path, detected)
        self._run_attack(wordlist, try_fn, "wordlist")

    def _pattern_attack(self, path, detected):
        info("Pattern attack — generating password variations")
        name = ask("Your name or keyword to mutate (or Enter to skip)")
        year_start = ask("Start year for date patterns (e.g. 1990, or Enter to skip)")

        passwords = []

        if name:
            for n in [name, name.lower(), name.upper(), name.capitalize()]:
                for suffix in ["","1","123","!","@","#","2023","2024","2025","01","99"]:
                    passwords.append(n+suffix)
                    passwords.append(suffix+n)

        if year_start.isdigit():
            y0 = int(year_start)
            for y in range(y0, 2026):
                for m in range(1,13):
                    for fmt in [f"{y}{m:02d}", f"{m:02d}{y}", f"{y}-{m:02d}",
                                 f"{m:02d}/{y}", f"{y}{m:02d}01"]:
                        passwords.append(fmt)

        passwords += ["qwerty","asdfgh","zxcvbn","qazwsx","1qaz2wsx",
                      "qwerty123","asdf1234","zxcv1234"]

        if not passwords:
            warn("No patterns generated — provide a name or year")
            return

        try_fn = self._get_try_fn(path, detected)
        self._run_attack(passwords[:5000], try_fn, "pattern attack")

    def _bruteforce(self, path, detected):
        warn("Brute force is slow — limited to printable ASCII, max 5 chars")
        max_len = ask("Max password length (1-5, default 4)")
        max_len = int(max_len) if max_len.isdigit() and 1 <= int(max_len) <= 5 else 4
        charset = ask("Charset: [1] digits only  [2] lower+digits  [3] all printable")
        if charset == "1":
            chars = "0123456789"
        elif charset == "2":
            chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        else:
            chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$"

        import itertools
        passwords = []
        for length in range(1, max_len+1):
            for combo in itertools.product(chars, repeat=length):
                passwords.append("".join(combo))

        info(f"Generated {len(passwords)} combinations — this may take a while…")
        try_fn = self._get_try_fn(path, detected)
        self._run_attack(passwords, try_fn, f"brute force (len≤{max_len})")

    def _manual_try(self, path, detected):
        info("Manual password testing — type passwords one by one")
        try_fn = self._get_try_fn(path, detected)
        while True:
            pwd = ask("Enter password to try (or 'q' to quit)")
            if pwd.lower() == "q": break
            if try_fn(pwd):
                print(f"\n  {C.BOLD}{C.GREEN}✔ CORRECT! Password: {pwd}{C.RESET}\n")
                break
            else:
                err("Incorrect password")

    def show_recommendations(self, detected):
        header("RECOVERY RECOMMENDATIONS")
        names = [d[0] for d in detected] if detected else []

        recs = {
            "LUKS": [
                "Use luksDump to inspect header: cryptsetup luksDump <device>",
                "If header is damaged: cryptsetup luksHeaderBackup / luksHeaderRestore",
                "Tool: cryptsetup-reencrypt for header recovery",
                "Last resort: check if a header backup exists",
            ],
            "ZIP (encrypted)": [
                "Tool: john --format=zip <file>  (John the Ripper)",
                "Tool: hashcat -m 13600 <hash> <wordlist>  (for AES-ZIP)",
                "Tool: fcrackzip -u -D -p wordlist.txt <file>",
                "If ZipCrypto: pkcrack (known-plaintext attack) may work",
            ],
            "OpenSSL enc": [
                "Tool: openssl enc -d -aes-256-cbc -pbkdf2 -in file -out out",
                "Tool: john --format=openssl <file>",
                "Note: without -pbkdf2 flag try legacy: openssl enc -d -aes-256-cbc -in file",
            ],
            "VeraCrypt / TrueCrypt": [
                "Tool: veracrypt --mount or GUI",
                "Header recovery: veracrypt --restore-headers",
                "Tool: hashcat -m 13711/13721/13731 for VeraCrypt hashes",
                "If header corrupt: try backup header (last 128KB of volume)",
            ],
            "GPG/PGP": [
                "Tool: gpg -d <file>  (requires private key)",
                "Tool: john --format=gpg <file>",
                "Tool: pgpcrack for dictionary attacks",
            ],
        }

        printed = False
        for name in names:
            if name in recs:
                print(f"\n  {c(C.BOLD+C.WHITE, name)}:")
                for r in recs[name]:
                    print(f"    {c(C.CYAN,'→')} {r}")
                printed = True

        if not printed:
            info("No specific recommendations — generic advice:")
            print(f"    {c(C.CYAN,'→')} Identify exact format first (use file, binwalk, xxd)")
            print(f"    {c(C.CYAN,'→')} Extract hash with tools like john2hash or hashcat extractors")
            print(f"    {c(C.CYAN,'→')} Run hashcat with --identify to detect hash type")

        print(f"\n  {c(C.DIM,'Note: all tools above are open-source and available via apt/brew')}\n")

    def menu(self):
        while True:
            header("MODULE 2 — ENCRYPTION RECOVERY")
            print(f"  {c(C.CYAN,'1')}. Identify encryption type of a file")
            print(f"  {c(C.CYAN,'2')}. Attempt password recovery")
            print(f"  {c(C.CYAN,'3')}. Show recovery tool recommendations")
            print(f"  {c(C.CYAN,'0')}. Back to main menu\n")
            ch = ask("Choose")

            if ch == "0": break
            elif ch in ("1","2","3"):
                fp = ask("Path to encrypted file")
                path = Path(fp)
                if not path.exists():
                    err(f"File not found: {fp}")
                    input(f"\n  {c(C.DIM,'Press Enter...')}")
                    continue
                detected = self.identify_file(path)
                if ch == "2":
                    self.attempt_recovery(path, detected)
                elif ch == "3":
                    self.show_recommendations(detected or [])
            else:
                warn("Invalid choice")

            input(f"\n  {c(C.DIM,'Press Enter to continue...')}")


# ══════════════════════════════════════════════════════════════
#  MAIN MENU
# ══════════════════════════════════════════════════════════════

def main():
    mem = MemoryForensics()
    cry = CryptoRecovery()

    while True:
        banner()
        print(f"  {C.BOLD}MAIN MENU{C.RESET}\n")
        print(f"  {c(C.CYAN,'1')}  🧠  Memory Forensics")
        print(f"       └─ Overview, process list, memory dump & string extraction\n")
        print(f"  {c(C.CYAN,'2')}  🔐  Encryption Recovery")
        print(f"       └─ Identify encryption, attempt password recovery, recommendations\n")
        print(f"  {c(C.CYAN,'0')}  ✖   Exit\n")

        ch = ask("Select module")
        if   ch == "1": mem.menu()
        elif ch == "2": cry.menu()
        elif ch == "0":
            print(f"\n  {c(C.DIM,'Goodbye.')}\n"); sys.exit(0)
        else:
            warn("Invalid choice")
            input(f"\n  {c(C.DIM,'Press Enter...')}")


if __name__ == "__main__":
    main()
