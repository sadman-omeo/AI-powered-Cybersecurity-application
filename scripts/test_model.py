import requests

BASE_URL = "http://127.0.0.1:8080"


def check_model():
    response = requests.get(
        f"{BASE_URL}/health",
        timeout=10
    )

    response.raise_for_status()

    print("Model server:", response.json())




def test_inference():

    models_response = requests.get(
        f"{BASE_URL}/v1/models",
        timeout=10
    )
    models_response.raise_for_status()

    model_id = models_response.json()["data"][0]["id"]

    payload = {
        "model": model_id,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity log analyst. "
                    "Use only the provided evidence. "
                    "Do not claim an attack is confirmed "
                    "without sufficient evidence."
                )
            },
            {
                "role": "user",
                "content": (
                    "/no_think\n"
                    "A log contains one failed login "
                    "with HTTP status 401. "
                    "Is this enough to confirm an attack? "
                    "Answer in one short sentence."
                )
            }
        ],
        "temperature": 0.1,
        "max_tokens": 120,
        "stream": False
    }

    response = requests.post(
        f"{BASE_URL}/v1/chat/completions",
        json=payload,
        timeout=120
    )

    response.raise_for_status()

    result = response.json()
    answer = result["choices"][0]["message"]["content"]

    print("\nAI response:")
    print(answer)




if __name__ == "__main__":

    try:
        check_model()
        test_inference()

    except requests.exceptions.RequestException as error:
        print("Could not communicate with the AI server:")
        print(error)

    except (KeyError, IndexError, TypeError) as error:
        print("Unexpected model response format:")
        print(error)