import os
import sys
import configparser
import stat
import hashlib


def load_config():
    config_path = os.path.expanduser("~/.clean_files")
    config = configparser.ConfigParser()

    defaults = {
        'permissions': '644',
        'bad_chars': ':;"\'*?$\\#|',
        'bad_char_sub': '_',
        'temp_extensions': '.tmp,.bak,~'
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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python file_organizer.py <directory_X> [directory_Y1] ...")
        sys.exit(1)

    target_dir = sys.argv[1]
    other_dirs = sys.argv[1:]

    print(scan_directories(other_dirs))

