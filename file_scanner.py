# file_scanner.py
import pefile, math, os

def get_entropy(data):
    if not data: return 0
    frequency = [float(data.count(chr(i))) for i in range(256)]
    entropy = -sum((f/len(data)) * math.log2(f/len(data)) for f in frequency if f > 0)
    return entropy

def scan_file(filepath):
    flags = []
    score = 0
    ext = os.path.splitext(filepath)[1].lower()

    if ext in ['.exe', '.dll', '.bat', '.ps1', '.vbs']:
        flags.append(("suspicious_extension", f"{ext} files can execute code"))
        score += 2

    if ext in ['.exe', '.dll']:
        try:
            pe = pefile.PE(filepath)
            entropy = get_entropy(open(filepath,'rb').read())
            if entropy > 7.0:
                flags.append(("high_entropy", "File appears packed or encrypted"))
                score += 2
            imports = [entry.dll.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT] if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else []
            dangerous = ['WriteProcessMemory', 'CreateRemoteThread', 'VirtualAllocEx']
            for imp in dangerous:
                if any(imp in str(pe.DIRECTORY_ENTRY_IMPORT) for _ in [1]):
                    flags.append(("dangerous_import", f"Uses {imp} — common in malware"))
                    score += 1
        except: pass

    risk = "LOW" if score == 0 else "MEDIUM" if score <= 2 else "HIGH"
    return risk, flags, score