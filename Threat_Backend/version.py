import os
import sys
import configparser

def get_version():
    config = configparser.ConfigParser()
    # In PyInstaller, the bundled file is at sys._MEIPASS
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    ini_path = os.path.join(base_path, 'version.ini')
    
    if os.path.exists(ini_path):
        config.read(ini_path)
        return config.get('Settings', 'Version', fallback='1.0.0')
    return '1.0.0'

APP_VERSION = get_version()
