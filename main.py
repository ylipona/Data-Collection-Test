"""
main.py — Entry point.
Starts Flask in a background thread and runs the Discord bot on the main thread.
Both share the same asyncio event loop reference so Flask can call bot coroutines.
"""

import asyncio
import os
import threading

from app import app as flask_app
from bot import bot, run_bot
import app as app_module   # so we can inject discord_bot & bot_loop


def start_flask(loop: asyncio.AbstractEventLoop):
    port = int(os.getenv("PORT", 5000))
    print(f"🌐  Flask listening on port {port}")
    flask_app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


def main():
    # Create a dedicated event loop for the Discord bot
    loop = asyncio.new_event_loop()

    # Inject references into the Flask app module BEFORE threads start
    app_module.discord_bot = bot
    app_module.bot_loop    = loop

    # Start Flask in a daemon thread
    t = threading.Thread(target=start_flask, args=(loop,), daemon=True)
    t.start()

    # Run the Discord bot on this thread (blocks until bot stops)
    print("🤖  Starting Discord bot…")
    run_bot(loop)


if __name__ == "__main__":
    main()
