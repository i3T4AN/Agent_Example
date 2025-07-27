#my_agent

This repository contains a minimal chat agent that uses OpenAI's API to engage in a conversational loop, retain history, and apply basic input validation and output sanitization.

## Overview

The agent loads API credentials from environment variables, reads and writes chat history to a JSON file, and sends user prompts to the OpenAI Chat API. It stores each interaction in a history file to maintain context across turns.

## Files

- `agent.py` – Implements the main chat loop. It loads the conversation history, processes user inputs, calls the OpenAI API, and appends responses to the history.
- `config.py` – Loads environment variables via `python-dotenv` and exposes the API key and model name.
- `guardrails.py` – Provides helper functions to validate input prompts and sanitize output from the API.
- `chat_history.json` – Stores the conversation history as a JSON array.
- `.env` – Local environment file with the `OPENAI_API_KEY` placeholder. This file is excluded from version control.
- `requirements.txt` – Lists the Python dependencies required to run the agent.
- `.gitignore` – Specifies files and directories to ignore in Git.

## Setup

1. Clone this repository.
2. Create a virtual environment and install dependencies:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. Copy the `.env` file and replace the placeholder `OPENAI_API_KEY` value with your actual OpenAI API key.
4. Run the chat agent:

   ```bash
   python agent.py
   ```

Type `exit` to end the session. The history of your conversation will be stored in `chat_history.json`.

## Notes

This project is intentionally simple. It does not include advanced error handling, streaming responses, or user interface beyond the command line. You are free to extend it to suit more demanding use cases.
