import subprocess, sys, os, difflib
FW='/home/iroha/projects/orientrise charge adapter/re/firmware.bin'
scripts=['hs3','hs4','hs5','hs6','hs7','hs9','hs10','hs12','hs13']
os.makedirs('buggy',exist_ok=True)
for s in scripts:
    src=subprocess.run(['git','show',f'a6035a0:{s}.py'],capture_output=True,text=True).stdout
    open(f'buggy/{s}.py','w').write(src)
    assert '0xFB7F' in src, f"{s}: extracted version is NOT the buggy one!"
    rb=subprocess.run([sys.executable,f'buggy/{s}.py',FW],capture_output=True,text=True)
    rf=subprocess.run([sys.executable,f'{s}.py',FW],capture_output=True,text=True)
    b,f=rb.stdout,rf.stdout
    tag="IDENTICAL" if b==f else "DIFFERS"
    print(f"{s}: {tag}  buggy={len(b)}B/rc{rb.returncode}  fixed={len(f)}B/rc{rf.returncode}")
    if rb.returncode: print("   BUGGY ERR:",rb.stderr.strip().splitlines()[-1])
    if rf.returncode: print("   FIXED ERR:",rf.stderr.strip().splitlines()[-1])
    if b!=f:
        for line in list(difflib.unified_diff(b.splitlines(),f.splitlines(),lineterm='',n=0))[2:30]:
            print("   "+line)
print("\n== hs13 UID/flash-size/DBGMCU lines (the 'MAC not UID-derived' negative claim) ==")
for ver,path in [("buggy","buggy/hs13.py"),("fixed","hs13.py")]:
    out=subprocess.run([sys.executable,path,FW],capture_output=True,text=True).stdout
    print(f"  [{ver}]")
    for ln in out.splitlines():
        if any(k in ln for k in ("UID","flashsize","DBGMCU")):
            print("    "+ln.strip())