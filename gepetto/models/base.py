import abc
import threading

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

def get_model(model, *args, **kwargs):
    """
    Instantiates a model based on its name
    :param model:
    :return:
    """
    if model == "gpt-3.5-turbo" or model == "gpt-4-1106-preview":
        from gepetto.models.openai import GPT
        return GPT(model)
    else:
        print(f"Warning:  {model} does not exist! Using default model (gpt-3.5-turbo).")
        from gepetto.models.openai import GPT
        return GPT("gpt-3.5-turbo")
