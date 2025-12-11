import os
import sys
import configparser
import stat


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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python file_organizer.py <directory_X> [directory_Y1] ...")
        sys.exit(1)

    target_dir = sys.argv[1]
    other_dirs = sys.argv[1:]

    print(get_file_info(target_dir))
