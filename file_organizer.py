import os
import sys
import configparser
import stat
import hashlib
import argparse
import re
import shutil
import time


def load_config():
    config_path = os.path.expanduser("~/.clean_files")
    config = configparser.ConfigParser()

    defaults = {
        'permissions': '644',
        'bad_chars': ':;"\'*?$\\#|',
        'bad_char_sub': '_',
        'temp_extensions': '.tmp,.bak,.swp,~'
    }

    if os.path.exists(config_path):
        config.read(config_path)
        if 'DEFAULT' in config:
            return config['DEFAULT']

    return defaults


CONFIG = load_config()


def get_file_info(filepath):
    """Gathers file metadata"""
    try:
        st = os.stat(filepath)
        return {
            'path': filepath,
            'name': os.path.basename(filepath),
            'size': st.st_size,
            'mtime': st.st_mtime,
            'mode': stat.S_IMODE(st.st_mode),
            'hash': None
        }
    except OSError:
        return None


def calculate_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as file:
            while True:
                data = file.read(65536)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()
    except (OSError, IOError):
        return None


def scan_directories(directories):
    files = []
    print("Scanning directories...")
    for directory in directories:
        for root, _, filenames in os.walk(directory):
            for name in filenames:
                path = os.path.join(root, name)
                info = get_file_info(path)
                if info:
                    info['hash'] = calculate_hash(path)
                    files.append(info)
    return files


def ask_user(prompt):
    """User interaction [y/n/a]."""
    while True:
        choice = input(f"{prompt} [y/n/a]: ").strip().lower()
        if choice in ['y', 'n', 'a']:
            return choice


def process_junk(files):
    print("\n--- Removing Empty and Temporary Files ---")
    temp_exts = CONFIG['temp_extensions'].split(',')
    action_all = None

    for file in files[:]:
        reason = ""
        if file['size'] == 0: reason = "Empty file"
        elif any(file['name'].endswith(ext) for ext in temp_exts): reason = "Temporary file"

        if reason:
            print(f"Found: {file['path']} ({reason})")
            if action_all:
                decision = action_all
            else:
                decision = ask_user("Delete?")

            if decision == 'a':
                action_all = 'a'
                decision = 'y'

            if decision == 'y':
                try:
                    os.remove(file['path'])
                    files.remove(file)
                    print("-> Deleted.")
                except OSError as e:
                    print(f"-> Error: {e}")


def process_duplicates(files):
    print("\n--- Handling Content Duplicates ---")
    groups = {}
    for file in files:
        if file['hash'] and file['size'] > 0:
            groups.setdefault(file['hash'], []).append(file)

    action_all = None

    for hash, group in groups.items():
        if len(group) > 1:
            group.sort(key=lambda x: x['mtime'])
            original = group[0]
            copies = group[1:]

            print(f"\nOriginal (oldest): {original['path']}")
            print(f"Duplicates ({len(copies)}):")
            for c in copies:
                print(f" - {c['path']}")

            if action_all:
                decision = action_all
            else:
                decision = ask_user("Delete duplicates?")

            if decision == 'a':
                action_all = 'a'
                decision = 'y'

            if decision == 'y':
                for copy in copies:
                    try:
                        os.remove(copy['path'])
                        if copy in files: files.remove(copy)
                        print(f"-> Deleted: {copy['path']}")
                    except OSError:
                        print(f"-> Error deleting {c['path']}")


def process_names(files):
    print("\n--- Fixing Filenames ---")
    bad_chars = CONFIG['bad_chars']
    sub = CONFIG['bad_char_sub']
    action_all = None

    pattern = '[]' + re.escape(bad_chars) + ']+'
    pattern_cleanup = '^' + re.escape(sub) + '+|' + re.escape(sub) + '+$'

    for file in files:
        original_name = file['name']
        new_name = re.sub(pattern, sub, original_name)
        name_part, ext_part = os.path.splitext(new_name)
        cleaned_name_part = re.sub(pattern_cleanup, '', name_part)
        final_new_name = cleaned_name_part + ext_part

        if final_new_name != original_name:
            print(f"File found: {file['path']}")
            print(f"Rename: {original_name} -> {final_new_name}")

            if action_all:
                decision = action_all
            else:
                decision = ask_user("Rename?")

            if decision == 'a':
                action_all = 'a'
                decision = 'y'

            if decision == 'y':
                new_path = os.path.join(os.path.dirname(file['path']), final_new_name)
                try:
                    os.rename(file['path'], new_path)
                    file['path'] = new_path
                    file['name'] = final_new_name
                    print("-> Renamed")
                except OSError as e:
                    print(f"-> Error: {e}")


def process_perms(files):
    print("\n--- Fixing Permissions ---")
    target_mode = int(CONFIG['permissions'], 8)
    action_all = None

    for file in files:
        if file['mode'] != target_mode:
            print(f"File found: {file['path']}")
            print(f"File {file['name']} permissions: {oct(file['mode'])[-3:]}. Target: {CONFIG['permissions']}")
            decision = action_all if action_all else ask_user("Fix?")
            if decision == 'a': action_all = 'a'; decision = 'y'

            if decision == 'y':
                try:
                    os.chmod(file['path'], target_mode)
                    file['mode'] = target_mode
                    print("-> Fixed.")
                except OSError as e:
                    print(f"-> Error: {e}")


def consolidate_files(files, main_dir):
    print(f"\n--- Consolidating to {main_dir} ---")
    main_dir_abs = os.path.abspath(main_dir)
    action_all = None

    for file in files:
        abs_path = os.path.abspath(file['path'])

        # if file is not inside main directory
        if not abs_path.startswith(main_dir_abs):
            dest = os.path.join(main_dir_abs, file['name'])

            if os.path.exists(dest):
                dest_stat = os.stat(dest)
                existing_mtime = dest_stat.st_mtime
                incoming_mtime = file['mtime']

                print(f"\nConflict found: File '{file['name']}' exists in both source ({file['path']}) and destination ({dest}).")

                if incoming_mtime > existing_mtime:
                    print(f"-> Incoming file (Y) is NEWER ({time.ctime(incoming_mtime)}).")
                    suggestion = "MOVE and REPLACE (Keep Newer)"
                    action_on_y = 'y'
                else:
                    print(f"-> Existing file (X) is NEWER or SAME DATE ({time.ctime(existing_mtime)}).")
                    suggestion = "SKIP (Keep Newer/Existing)"
                    action_on_y = 'n'

                print(f"Suggestion: {suggestion}")

                decision = action_all if action_all else ask_user("Execute suggestion? (y/n/a)")
                if decision == 'a': action_all = 'a'; decision = 'y'

                if decision == 'y':
                    if action_on_y == 'y':
                        try:
                            shutil.move(file['path'], dest)
                            file['path'] = dest
                            print("-> Moved and replaced older version.")
                        except OSError as e:
                            print(f"-> Error moving file: {e}")
                    else:
                        try:
                            os.remove(f['path'])
                            print("-> Kept existing file in X. Deleted older file from source.")
                        except OSError as e:
                            print(f"-> Error deleting source file: {e}")

                continue

            print(f"File outside main directory: {file['path']}")
            decision = action_all if action_all else ask_user("Move to X?")
            if decision == 'a': action_all = 'a'; decision = 'y'

            if decision == 'y':
                try:
                    shutil.move(file['path'], dest)
                    file['path'] = dest
                    print("-> Moved.")
                except OSError as e:
                    print(f"-> Error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("main_directories")
    parser.add_argument("extra_directories", nargs='*')

    parser.add_argument("-j", "--junk", action="store_true")
    parser.add_argument("-d", "--duplicates", action="store_true")
    parser.add_argument("-n", "--names", action="store_true")
    parser.add_argument("-p", "--permissions", action="store_true")
    parser.add_argument("-m", "--move", action="store_true")
    parser.add_argument("-a", "--all", action="store_true")

    args = parser.parse_args()

    directories_to_scan = [args.main_directories] + args.extra_directories

    try:
        all_files = scan_directories(directories_to_scan)
    except Exception as e:
        print(f"Error during scanning: {e}")
        sys.exit(1)

    print(f"Scanned {len(all_files)} files.")

    if not all_files:
        print("No files found.")
        sys.exit(0)


    if args.all or args.junk:
        process_junk(all_files)

    if args.all or args.dupes:
        process_duplicates(all_files)

    if args.all or args.names:
        process_names(all_files)

    if args.all or args.perms:
        process_perms(all_files)

    if args.all or args.move:
        consolidate_files(all_files, args.main_dir)

    if not (args.all or args.junk or args.dupes or args.names or args.perms or args.move):
        print("\nNo action selected.")

