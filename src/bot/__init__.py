"""
GE_Phantom — Bot Module

Auto-farm bot driven by sniffer radar data + keyboard/mouse automation.

Components:
    input.py       — Win32 input (keybd_event + mouse_event)
    controller.py  — Decision loop (find → move → attack → repeat)
    main.py        — Entry point (sniffer + bot loop)
    memory.py      — Process memory access (from Phase 2)
    range_modifier.py — Attack range finder (from Phase 2)
"""

from src.bot.input import InputController, GEInput, GameWindow, VK, SKILL_KEYS
from src.bot.controller import BotController, BotConfig, BotState, BotStats
