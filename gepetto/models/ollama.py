import functools
import re
import requests

import ida_kernwin

from gepetto.models.base import LanguageModel
import gepetto.config

config = gepetto.config.GepettoConfig()

class Ollama(LanguageModel):
    def __init__(self, model):
        self.model = model

    def __str__(self):
        return self.model

    def query_model(self, query, cb, max_tokens=6500):
        """
        Function which sends a query to ollama local API and calls a callback when the response is available.
        Blocks until the response is received
        :param query: The request to send to ollama
        :param cb: Function to which the response will be passed to.
        """
        try:
            response = requests.post(
                url=f"{config.ollama_base_url}/api/generate/",
                headers={"Content-Type": "application/json"},
                json={
                    "model": str(self.model),
                    "prompt": query,
                    "stream": False
                },
                stream=False,
                timeout=20*60 # 20 min
            )

            response.raise_for_status()
        except Exception as e:
            print(_("General exception encountered while running the query: {error}").format(error=str(e)))
            return

        response.encoding = "utf-8"
        json_response = response.json()
        error = json_response.get("error", None)

        if error is not None:
            if "maximum context length is" not in error:
                print(_("{model} could not complete the request: {error}").format(model=self.model, error=str(e)))
                return

            # Context length exceeded. Determine the max number of tokens we can ask for and retry.
            m = re.search(r'maximum context length is (\d+) tokens, however you requested \d+ tokens \((\d+) in your '
                        r'prompt;', str(e))
            if not m:
                print(_("{model} could not complete the request: {error}").format(model=self.model, error=str(e)))
                return

            (hard_limit, prompt_tokens) = (int(m.group(1)), int(m.group(2)))
            max_tokens = hard_limit - prompt_tokens
            if max_tokens < 750:
                print("Unfortunately, this function is too big to be analyzed with the model's current API limits.")
                return

            print(_("Context length exceeded! Reducing the completion tokens to "
                    "{max_tokens}...").format(max_tokens=max_tokens))
            self.query_model(query, cb, max_tokens)

        if not json_response.get("done", False):
            print("No data received from Ollama.")
            return

        ida_kernwin.execute_sync(functools.partial(cb, response=json_response["response"]),
                        ida_kernwin.MFF_WRITE)
