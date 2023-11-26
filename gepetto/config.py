import configparser
import gettext
import os

gettext.install("gepetto")

class GepettoConfig:
    """
    Class that handles the configuration of the plugin.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, config_path='config.ini'):
        if hasattr(self, 'config_path'):
            return

        self.config_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), config_path)
        self.translate = None
        self.model = None
        self.ollama_base_url = None

    def load(self, model_loader):
        """
        Loads the configuration of the plugin from the INI file. Sets up the correct locale and language model.
        :return:
        """
        config = configparser.RawConfigParser()
        config.read(self.config_path)

        # Set up translations
        language = config.get('Gepetto', 'LANGUAGE')
        self.translate = gettext.translation('gepetto',
                                        os.path.join(os.path.abspath(os.path.dirname(__file__)), "locales"),
                                        fallback=True,
                                        languages=[language])
        self.translate.install()

        try:
            import openai
            # Get API keys
            if not config.get('OpenAI', 'API_KEY'):
                openai.api_key = os.getenv("OPENAI_API_KEY")
            else:
                openai.api_key = config.get('OpenAI', 'API_KEY')
                print(f"Key set to {openai.api_key}")

            # Get OPENAPI proxy
            if not config.get('OpenAI', 'OPENAI_PROXY'):
                openai.proxy = os.getenv("OPENAI_PROXY")
            else:
                openai.proxy = config.get('OpenAI', 'OPENAI_PROXY')
        except ImportError:
            print("No OpenAI module found, only local LLMs will be used.")

        # Get Ollama base URL
        if not config.get('Ollama', 'OLLAMA_BASE_URL'):
            self.ollama_base_url = os.getenv("OLLAMA_BASE_URL")
        else:
            self.ollama_base_url = config.get('Ollama', 'OLLAMA_BASE_URL')

        # Select model
        requested_model = config.get('Gepetto', 'MODEL')
        self.model = model_loader(requested_model)

    def update(self, section, option, new_value):
        """
        Updates a single entry in the configuration.
        :param section: The section in which the option is located
        :param option: The option to update
        :param new_value: The new value to set
        :return:
        """
        config = configparser.RawConfigParser()
        config.read(self.config_path)
        config.set(section, option, new_value)
        with open(self.config_path, "w", encoding="utf-8") as f:
            config.write(f)
