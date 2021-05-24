import configparser
import sys


class Config:
    """
    A static class that retrieves defined values from a configuration file and distributes them throughout the application.
    """
    __config_file_name = 'config.ini'
    __config = None

    @staticmethod
    def __init_config():
        """
        Opens a config file, load configuration to static field
        """
        try:
            open(Config.__config_file_name)
            Config.__config = configparser.ConfigParser()
            Config.__config.read(Config.__config_file_name)
        except IOError:
            sys.exit(f'Could not find {Config.__config_file_name} file, make sure it exists.')

    @staticmethod
    def get_config(name):
        """
        Obtains a user-specified value from config file

        :param name:
        :type name: str
        :return: value of field in configuration
        :rtype string
        """
        if Config.__config is None:
            Config.__init_config()

        return dict(Config.__config)['DEFAULT'][name]
