import configparser
import sys


class Config:
    __config_file_name = 'config.ini'
    __config = None

    @staticmethod
    def __init_config():
        try:
            # Check if config file exists
            open(Config.__config_file_name)
            Config.__config = configparser.ConfigParser()
            Config.__config.read(Config.__config_file_name)
        except IOError:
            sys.exit(f'Could not find {Config.__config_file_name} file, make sure it exists.')

    @staticmethod
    def get_config(name):
        if Config.__config is None:
            Config.__init_config()

        return dict(Config.__config)['DEFAULT'][name]
