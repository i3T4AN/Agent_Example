def validate_input(prompt: str) -> str:
    prompt = prompt.strip()
    if not prompt:
        raise ValueError("Empty input not allowed.")
    return prompt


def sanitize_output(output: str) -> str:
    return output.strip()
