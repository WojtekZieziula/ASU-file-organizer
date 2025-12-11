import os
import sys
import configparser
import stat
import hashlib
import argparse


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
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(65536)
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
    print("\n--- [MODE: JUNK] Removing Empty and Temporary Files ---")
    temp_exts = CONFIG['temp_extensions'].split(',')
    action_all = None

    for f in files[:]:
        reason = ""
        if f['size'] == 0: reason = "Empty file"
        elif any(f['name'].endswith(ext) for ext in temp_exts): reason = "Temporary file"

        if reason:
            print(f"Found: {f['path']} ({reason})")
            decision = action_all if action_all else ask_user("Delete?")
            if decision == 'a': action_all = 'a'; decision = 'y'

            if decision == 'y':
                try:
                    os.remove(f['path'])
                    files.remove(f)
                    print("-> Deleted.")
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
