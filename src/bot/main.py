"""
GE_Phantom — Auto-Farm Bot Entry Point

Starts the packet sniffer in a background thread, waits for radar data,
then runs the bot decision loop.

Usage (run as Administrator):
    python -m src.bot.main --keyboard-only          # test keyboard only
    python -m src.bot.main --no-input               # radar only, no input
    python -m src.bot.main --attack-mode space       # full bot
    python -m src.bot.main --skills 0:5,1:8,2:10    # with skill rotation
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
import time

from src.sniffer.capture import GESniffer
from src.data.router import ClientRouter
from src.bot.input import GEInput, GameWindow, InputController
from src.bot.controller import BotController, BotConfig

log = logging.getLogger("ge_bot")

# Characters — known party
MY_CHARS = ["KajaDesigner", "Karjalainen22", "Scoutz"]

# Known attack ranges for our characters (from Phase 2 live capture).
KNOWN_PLAYER_RANGES = {850.0, 803.0, 730.0}

# Position sanity: reject position updates that jump more than this many units.
# Normal walking speed won't exceed ~500 units between COMBAT_UPDATE ticks.
MAX_POSITION_JUMP = 5000


def _try_identify_player_from_combat(state) -> bool:
    """Try to identify the player entity from COMBAT_UPDATE data."""
    for eid, ci in state.characters.items():
        if ci.attack_range in KNOWN_PLAYER_RANGES:
            ent = state.entities.get(eid)
            if ent and (ent.x or ent.y):
                state.player_entity_id = eid
                state.player_x = ent.x
                state.player_y = ent.y
                log.info(
                    "Identified player from COMBAT_UPDATE: eid=%d range=%.0f pos=(%d,%d)",
                    eid, ci.attack_range, ent.x, ent.y,
                )
                return True
    return False


def wait_for_player(state, timeout: float = 60.0) -> bool:
    """Wait until we can identify the player position."""
    start = time.time()
    last_report = 0.0

    while time.time() - start < timeout:
        if state.player_entity_id and (state.player_x or state.player_y):
            return True
        if state.characters and _try_identify_player_from_combat(state):
            return True

        now = time.time()
        elapsed = now - start
        if (now - last_report) >= 5.0:
            n_ent = len(state.entities)
            n_chars = len(state.characters)
            top_pkts = sorted(state.packet_counts.items(), key=lambda x: -x[1])[:5]
            pkt_summary = ", ".join(f"{n}={c}" for n, c in top_pkts) if top_pkts else "none yet"
            log.info(
                "  waiting... %.0fs | pkts=%d entities=%d chars=%d | top: %s",
                elapsed, state.total_packets, n_ent, n_chars, pkt_summary,
            )
            last_report = now

        time.sleep(0.5)
    return False


def parse_skills(s: str) -> list[tuple[int, float]]:
    """Parse skill rotation string like '0:5,1:8,2:10'."""
    if not s:
        return []
    result = []
    for pair in s.split(","):
        parts = pair.strip().split(":")
        if len(parts) == 2:
            result.append((int(parts[0]), float(parts[1])))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="GE_Phantom Auto-Farm Bot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--range", type=float, default=0.0,
                        help="Attack range override (0 = auto-detect from packets)")
    parser.add_argument("--tick", type=float, default=0.5,
                        help="Decision loop interval in seconds (default: 0.5)")
    parser.add_argument("--attack-mode", choices=["space", "ctrl_a"], default="space",
                        help="Attack method: 'space' or 'ctrl_a'")
    parser.add_argument("--skills", type=str, default="",
                        help="Skill rotation as 'slot:cooldown,...'")
    parser.add_argument("--iface", type=str, default=None,
                        help="Network interface for sniffer")
    parser.add_argument("--move-radius", type=int, default=200,
                        help="Click radius from screen center for movement (px)")
    parser.add_argument("--no-input", action="store_true",
                        help="Radar-only mode: no input sent at all")
    parser.add_argument("--keyboard-only", action="store_true",
                        help="Keyboard-only mode: send keys via PostMessage, no mouse")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    # Logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Admin check
    if not args.no_input and not InputController.is_admin():
        log.error("Not running as Administrator!")
        sys.exit(1)

    # Find game window
    window = GameWindow()
    if not args.no_input:
        if not window.find():
            log.error("GE window not found. Is the game running?")
            sys.exit(1)
        rect = window.get_rect()
        log.info("Found GE window: hwnd=0x%X rect=%s", window.hwnd,
                 f"{rect.width}x{rect.height}" if rect else "?")

    # Set up sniffer → router
    sniffer = GESniffer(iface=args.iface)
    router = ClientRouter(my_chars=MY_CHARS, reassemble=True)
    sniffer.on_packet(lambda pkt: router.process_packet(pkt))

    router.on_client_discovered(
        lambda s: log.info("[+] Client discovered: %s", s.label)
    )

    # Start sniffer in background thread
    sniffer_thread = threading.Thread(
        target=sniffer.start, daemon=True, name="sniffer",
    )
    sniffer_thread.start()
    log.info("Sniffer started in background thread")

    # Wait for player position
    log.info("Waiting for player position...")
    radar = router.global_state
    if not wait_for_player(radar, timeout=120):
        log.error("Timed out waiting for player position. Are you in-game?")
        sys.exit(1)

    log.info(
        "Player detected: eid=%d pos=(%d, %d)",
        radar.player_entity_id, radar.player_x, radar.player_y,
    )

    # Collect our 3 character entity IDs (sequential from anchor)
    anchor_eid = radar.player_entity_id
    our_eids: set[int] = {anchor_eid, anchor_eid + 1, anchor_eid + 2}
    for eid in sorted(our_eids):
        ci = radar.characters.get(eid)
        ent = radar.entities.get(eid)
        range_str = f"range={ci.attack_range:.0f}" if ci else "no-ci"
        pos_str = f"pos=({ent.x},{ent.y})" if ent else "no-ent"
        log.info("  our char eid=%d %s %s", eid, range_str, pos_str)

    # Subscribe to keep player position updated.
    # ONLY accept COMBAT_UPDATE ("combat") — ENTITY_POSITION has garbage x/y for
    # player characters (different field layout). Also sanity-check jumps.
    def _track_player(event_type: str, data: dict) -> None:
        if event_type != "combat":
            return
        eid = data.get("entity_id", 0)
        if eid not in our_eids:
            return
        x = data.get("x")
        y = data.get("y")
        if x is None or y is None or (x == 0 and y == 0):
            return
        # Sanity check: reject huge jumps (garbage data)
        if radar.player_x and radar.player_y:
            dx = abs(x - radar.player_x)
            dy = abs(y - radar.player_y)
            if dx > MAX_POSITION_JUMP or dy > MAX_POSITION_JUMP:
                return  # silently reject garbage
        radar.player_entity_id = eid
        radar.player_x = x
        radar.player_y = y

    radar.on_update(_track_player)
    log.info("Player tracking active for eids %s", sorted(our_eids))

    if args.no_input:
        log.info("Radar-only mode — tracking entities, no input sent")
        _radar_only_loop(radar, our_eids)
        return

    if args.keyboard_only:
        log.info("Keyboard-only mode — testing PostMessage keys, no mouse")
        _keyboard_only_loop(radar, our_eids, window)
        return

    # Build bot config
    config = BotConfig(
        attack_range=args.range,
        tick_interval=args.tick,
        move_click_radius=args.move_radius,
        attack_mode=args.attack_mode,
        skill_rotation=parse_skills(args.skills),
    )

    inp = GEInput(window)
    bot = BotController(radar, inp, config)

    log.info("Bot config: range=%.0f tick=%.1fs mode=%s skills=%s",
             config.attack_range or bot.get_attack_range(),
             config.tick_interval,
             config.attack_mode,
             config.skill_rotation or "none")
    log.info("Starting bot loop... Press Ctrl+C to stop")

    window.activate()
    time.sleep(0.3)

    _run_with_status(bot)


def _keyboard_only_loop(state, our_eids: set[int], window: GameWindow) -> None:
    """Keyboard-only test: cycle through skill keys, show radar status.

    Tests if PostMessage keyboard input reaches the game.
    Does NOT move the mouse at all.
    """
    from src.bot.input import GEInput, VK

    inp = GEInput(window)
    send_count = 0

    # Test keys: Q W E R T (skill row 1), then SPACE, F1-F3
    test_keys = [
        (VK.Q, "Q"), (VK.W, "W"), (VK.E, "E"), (VK.R, "R"), (VK.T, "T"),
        (VK.SPACE, "SPACE"),
        (VK.F1, "F1"), (VK.F2, "F2"), (VK.F3, "F3"),
    ]

    log.info("Keyboard test: sending keys via PostMessage to hwnd=0x%X", window.hwnd)
    log.info("Keys to test: %s", " ".join(name for _, name in test_keys))
    log.info("Watch the game for skill activations. Ctrl+C to stop.")

    try:
        idx = 0
        while True:
            vk, name = test_keys[idx % len(test_keys)]
            inp.send_key(vk)
            send_count += 1
            idx += 1

            line = (
                f"  sent {name} (#{send_count}) | "
                f"pos=({state.player_x},{state.player_y}) "
                f"pkt={state.total_packets}"
            )
            print(f"\r{line:<100s}", end="", flush=True)
            time.sleep(2.0)
    except KeyboardInterrupt:
        print()
        log.info("Keyboard test stopped. Sent %d keys", send_count)


def _run_with_status(bot: BotController) -> None:
    """Run the bot loop with periodic status output."""
    bot._running = True
    last_status = 0.0
    STATUS_INTERVAL = 3.0

    try:
        while bot._running:
            bot.tick()

            now = time.time()
            if (now - last_status) >= STATUS_INTERVAL:
                print(f"\r  {bot.status_line()}", end="", flush=True)
                last_status = now

            time.sleep(bot.config.tick_interval)
    except KeyboardInterrupt:
        print()
        log.info("Bot stopped by user")
        log.info(
            "Stats: attacks=%d skills=%d moves=%d",
            bot.stats.attacks, bot.stats.skills_used, bot.stats.move_commands,
        )
    finally:
        bot._running = False


def _radar_only_loop(state, our_eids: set[int]) -> None:
    """Radar-only: print entity counts and nearest monster info."""
    try:
        while True:
            monsters = [
                e for e in state.entities.values()
                if e.entity_type == "monster" and (e.x or e.y)
            ]

            nearest_str = "none"
            if monsters and state.player_entity_id:
                dists = []
                for m in monsters:
                    d = state.distance_to_player(m.entity_id)
                    if d is not None:
                        dists.append((d, m))
                if dists:
                    dists.sort()
                    top3 = [f"{d:.0f}" for d, _ in dists[:3]]
                    nearest_str = f"eid:{dists[0][1].entity_id} [{','.join(top3)}]"

            our_ranges = []
            for eid in sorted(our_eids):
                ci = state.characters.get(eid)
                if ci and ci.attack_range > 0:
                    our_ranges.append(f"{ci.attack_range:.0f}")

            line = (
                f"  ent={len(state.entities)} mon={len(monsters)} "
                f"pos=({state.player_x},{state.player_y}) "
                f"near={nearest_str} "
                f"range=[{','.join(our_ranges)}] "
                f"pkt={state.total_packets} {state.stats.rate():.0f}/s"
            )
            print(f"\r{line:<120s}", end="", flush=True)
            time.sleep(1.0)
    except KeyboardInterrupt:
        print()
        log.info("Radar-only mode stopped")


if __name__ == "__main__":
    main()
