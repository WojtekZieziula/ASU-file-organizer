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
                    except OSError as e:
                        print(f"-> Error deleting {copy['path']}")


def process_name_conflicts(files, main_dir):
    print("\n--- Resolving Name Conflicts (Keep Newer) ---")

    name_groups = {}
    for f in files:
        name_groups.setdefault(f['name'], []).append(f)

    action_all = None

    for name, group in name_groups.items():
        if len(group) > 1:
            group.sort(key=lambda x: x['mtime'], reverse=True)

            keeper = group[0]
            deleted_copies = group[1:]

            print(f"\nConflict found for name: {name}")
            print(f"Keeper (Newest): {keeper['path']} ({time.ctime(keeper['mtime'])})")
            print(f"Old versions ({len(deleted_copies)}):")
            for c in deleted_copies:
                print(f" - {c['path']} ({time.ctime(c['mtime'])})")

            decision = action_all if action_all else ask_user("Delete older versions?")
            if decision == 'a': action_all = 'y'; decision = 'y'

            if decision == 'y':
                for c in deleted_copies:
                    try:
                        os.remove(c['path'])
                        files.remove(c)
                        print(f"-> Deleted older copy: {c['path']}")
                    except OSError as e:
                        print(f"-> Error deleting {c['path']}: {e}")


def process_names(files):
    print("\n--- Fixing Filenames ---")
    bad_chars = CONFIG['bad_chars']
    sub = CONFIG['bad_char_sub']
    action_all = None

    pattern_problem_chars = '[' + re.escape(bad_chars) + ']+'
    pattern_cleanup_edges = '^' + re.escape(sub) + '+|' + re.escape(sub) + '+$'

    for file in files:
        original_name = file['name']

        intermediate_name = re.sub(pattern_problem_chars, sub, original_name)
        name_part, ext_part = os.path.splitext(intermediate_name)
        cleaned_name_part = re.sub(pattern_cleanup_edges, '', name_part)

        if not cleaned_name_part:
            cleaned_name_part = "unnamed_file"

        final_new_name = cleaned_name_part + ext_part

        if final_new_name != original_name:
            print(f"File found: {file['path']}")

            base_dir = os.path.dirname(file['path'])
            new_path = os.path.join(base_dir, final_new_name)

            if os.path.exists(new_path):
                counter = 1
                while os.path.exists(new_path):
                    new_path = os.path.join(base_dir, f"{cleaned_name_part}_{counter}{ext_part}")
                    counter += 1
                final_new_name = os.path.basename(new_path)
                print(f"-> Collision detected! New target: {final_new_name}")

            print(f"Rename: {original_name} -> {final_new_name}")

            if action_all:
                decision = action_all
            else:
                decision = ask_user("Rename?")

            if decision == 'a':
                action_all = 'a'
                decision = 'y'

            if decision == 'y':
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
    print(f"\n--- Moving remaining files to {main_dir} ---")
    main_dir_abs = os.path.abspath(main_dir)

    for file in files:
        abs_path = os.path.abspath(file['path'])

        if not abs_path.startswith(main_dir_abs):
            dest = os.path.join(main_dir_abs, file['name'])

            if os.path.exists(dest):
                print(f"Warning: Destination file already exists: {dest}. Skipping move.")
                continue

            try:
                shutil.move(file['path'], dest)
                file['path'] = dest
                print(f"-> Moved standard file: {file['name']}")
            except OSError as e:
                print(f"-> Error moving file: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Simple tool to clean and organize files across multiple folders.",
        epilog="How to use: python3 file_organizer.py [MAIN_DIR] [EXTRA_DIRS...] [FLAGS]"
    )

    parser.add_argument("main_directory",
                        help="The main folder where files will be moved/kept.")
    parser.add_argument("extra_directories", nargs='*',
                        help="Additional folders to scan.")

    parser.add_argument("-j", "--junk", action="store_true",
                        help="Delete empty files and temporary files (based on extensions).")
    parser.add_argument("-d", "--duplicates", action="store_true",
                        help="Find and delete exact file copies (keeps the oldest version).")
    parser.add_argument("-c", "--name-conflicts", action="store_true",
                        help="Fix cases where different files have the same name (keeps the newest version).")
    parser.add_argument("-n", "--names", action="store_true",
                        help="Fix filenames by replacing invalid characters with a separator from config.")
    parser.add_argument("-p", "--permissions", action="store_true",
                        help="Set file permissions to the standard value (defined in config).")
    parser.add_argument("-m", "--move", action="store_true",
                        help="Move all files from extra folders into the main folder.")
    parser.add_argument("-a", "--all", action="store_true",
                        help="Run all the above actions at once.")

    args = parser.parse_args()

    directories_to_scan = [args.main_directory] + args.extra_directories

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

    if args.all or args.duplicates:
        process_duplicates(all_files)

    if args.all or args.name_conflicts:
        process_name_conflicts(all_files, args.main_directory)

    if args.all or args.names:
        process_names(all_files)

    if args.all or args.permissions:
        process_perms(all_files)

    if args.all or args.move:
        consolidate_files(all_files, args.main_directory)

    if not (args.all or args.junk or args.duplicates or args.name_conflicts or args.names or args.permissions or args.move):
        print("\nNo action selected.")
