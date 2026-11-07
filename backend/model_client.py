
import requests


class LocalTokenizer:

    def __init__(self, base_url="http://127.0.0.1:8080"):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def count_messages(self, messages):

        # Apply the model's chat template
        response = self.session.post(
            f"{self.base_url}/apply-template",
            json={"messages": messages},
            timeout=30
        )

        response.raise_for_status()
        prompt = response.json()["prompt"]

        # Count tokens using the actual model tokenizer
        response = self.session.post(
            f"{self.base_url}/tokenize",
            json={
                "content": prompt,
                "add_special": False,
                "parse_special": True
            },
            timeout=30
        )

        response.raise_for_status()
        tokens = response.json()["tokens"]

        return len(tokens)
