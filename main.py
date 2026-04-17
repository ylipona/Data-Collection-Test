"""
main.py — Entry point.
Starts Flask in a background thread and runs the Discord bot on the main thread.
"""

import asyncio
import os
import threading

from app import app as flask_app
from bot import bot, run_bot
import app as app_module


def start_flask(loop: asyncio.AbstractEventLoop):
    port = int(os.getenv("PORT", 5000))
    print(f"🌐  Flask listening on port {port}")
    flask_app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


def main():
    loop = asyncio.new_event_loop()

    app_module.discord_bot = bot
    app_module.bot_loop    = loop

    t = threading.Thread(target=start_flask, args=(loop,), daemon=True)
    t.start()

    print("🤖  Starting Discord bot…")
    run_bot(loop)


if __name__ == "__main__":
    main()
