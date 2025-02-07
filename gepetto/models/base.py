import abc
import requests
import threading

from ..config import GepettoConfig
config = GepettoConfig()

class LanguageModel(abc.ABC):
    def __init__(self):
        self.model = NotImplemented

    @abc.abstractmethod
    def query_model(self, query, cb):
        pass

    def query_model_async(self, query, cb):
        """
        Function which sends a query to {model} and calls a callback when the response is available.
        :param query: The request to send to {model}
        :param cb: The function to which the response will be passed to.
        """
        print(_("Request to {model} sent...").format(model=str(self.model)))
        t = threading.Thread(target=self.query_model, args=[query, cb])
        t.start()

def get_model(model):
    """
    Instantiates a model based on its name
    :param model:
    :return:
    """
    if model in get_openai_available_models():
        from .openai import GPT
        return GPT(model)
    if model in get_local_available_models():
        from .ollama import Ollama
        return Ollama(model)

    print(f"Warning:  {model} does not exist! Using default model (gpt-3.5-turbo).")
    from .openai import GPT
    return GPT("gpt-3.5-turbo")

def get_all_available_models():
    return get_openai_available_models() + get_local_available_models()

def get_openai_available_models():
    return ["gpt-3.5-turbo", "gpt-4-1106-preview"]

def get_local_available_models():
    try:
        response = requests.get(
            f"{config.ollama_base_url}/api/tags",
            timeout=5*60 # 5 min
        )
        response.raise_for_status()
    except Exception as e:
        print("No local models found.")
        print("Details: {error}".format(error=str(e)))
        return []
        
    response.encoding = "utf-8"
    json_response = response.json()

    return [model['name'] for model in json_response.get('models', [])]
