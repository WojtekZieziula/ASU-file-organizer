import os
import sys
import configparser
import stat
import hashlib
import argparse
import re


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
                action_all = 'a';
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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python file_organizer.py <directory_X> [directory_Y1] ...")
        sys.exit(1)


    parser = argparse.ArgumentParser()

    parser.add_argument("main_directory")
    parser.add_argument("extra_directories", nargs='*')

    parser.add_argument("-j", "--junk", action="store_true")
    parser.add_argument("-n", "--names", action="store_true")
    parser.add_argument("-d", "--duplicates", action="store_true")


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

    if args.junk:
        process_junk(all_files)

    if  args.duplicates:
        process_duplicates(all_files)

    if args.names:
        process_names(all_files)
