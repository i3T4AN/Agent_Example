import json
import openai
from config import OPENAI_API_KEY, MODEL
from guardrails import validate_input, sanitize_output

HISTORY_FILE = "chat_history.json"

openai.api_key = OPENAI_API_KEY

def load_history():
    try:
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

def save_history(history):
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

def chat():
    history = load_history()
    print("Agent ready. Type 'exit' to quit.")

    while True:
        try:
            user_input = input("You: ")
            if user_input.lower() == "exit":
                break

            user_input = validate_input(user_input)

            history.append({"role": "user", "content": user_input})
            response = openai.ChatCompletion.create(
                model=MODEL,
                messages=history
            )
            reply = sanitize_output(response.choices[0].message.content)
            print(f"Agent: {reply}")
            history.append({"role": "assistant", "content": reply})
            save_history(history)

        except Exception as e:
            print(f"[Error] {e}")

if __name__ == "__main__":
    chat()
