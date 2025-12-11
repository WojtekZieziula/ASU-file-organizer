import os
import configparser

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

print(CONFIG.get('permissions'))
print(CONFIG.get('bad_chars'))
print(CONFIG.get('temp_extensions'))
print(CONFIG.get('bad_char_sub'))

