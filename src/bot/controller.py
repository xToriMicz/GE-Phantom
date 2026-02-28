"""
GE_Phantom — Bot Controller

Decision loop that reads RadarState and drives GEInput.
Finds nearest monster → moves toward it → attacks → repeats.

Architecture:
    GESniffer → ClientRouter → RadarState
                                   ↓
                             BotController (this file)
                              ├── find_nearest_monster()
                              ├── is_in_range()
                              ├── move_toward()
                              └── attack()
                                   ↓
                             GEInput (keybd_event / mouse_event)
"""

from __future__ import annotations

import math
import time
import logging
from dataclasses import dataclass, field
from enum import Enum, auto

from src.data.state import RadarState, Entity, CharacterInfo
from src.bot.input import GEInput, VK

log = logging.getLogger(__name__)


# ---- Bot states ----

class BotState(Enum):
    IDLE = auto()       # No monsters, nothing to do
    MOVING = auto()     # Walking toward a monster
    ATTACKING = auto()  # In range, attacking
    LOOTING = auto()    # Picking up items (future)


# ---- Configuration ----

@dataclass
class BotConfig:
    """Bot behavior configuration."""
    # Attack range override (0 = use from packet data)
    attack_range: float = 0.0
    # How often the decision loop ticks (seconds)
    tick_interval: float = 0.5
    # Movement click radius from screen center (pixels)
    move_click_radius: int = 200
    # How close is "close enough" to stop moving (world units)
    close_enough: float = 100.0
    # Max time to keep moving toward same target before re-evaluating (seconds)
    move_timeout: float = 15.0
    # Re-attack interval while attacking (seconds) — press SPACE periodically
    attack_interval: float = 2.0
    # Skill rotation: list of (slot_index, cooldown_seconds)
    skill_rotation: list[tuple[int, float]] = field(default_factory=list)
    # Max entity age (seconds) — ignore entities not seen recently
    max_entity_age: float = 30.0
    # Auto-attack mode: "space" (SPACE) or "ctrl_a" (Ctrl+A)
    attack_mode: str = "space"


# ---- Bot Controller ----

class BotController:
    """Drives the auto-farm loop based on radar data."""

    def __init__(
        self,
        state: RadarState,
        inp: GEInput,
        config: BotConfig | None = None,
    ):
        self.state = state
        self.inp = inp
        self.config = config or BotConfig()
        self.bot_state = BotState.IDLE
        self._running = False
        self._paused = False
        self._target_eid: int = 0
        self._move_start: float = 0.0
        self._last_attack: float = 0.0
        self._skill_cooldowns: dict[int, float] = {}  # slot -> last_used timestamp
        self._stats = BotStats()

    # ---- Monster finding ----

    def find_nearest_monster(self) -> Entity | None:
        """Find the nearest monster with a known position."""
        now = time.time()
        best: Entity | None = None
        best_dist = float("inf")

        if not self.state.player_entity_id:
            return None

        for ent in self.state.entities.values():
            if ent.entity_type != "monster":
                continue
            if ent.x == 0 and ent.y == 0:
                continue
            if (now - ent.last_seen) > self.config.max_entity_age:
                continue
            dist = self.state.distance_to_player(ent.entity_id)
            if dist is not None and dist < best_dist:
                best_dist = dist
                best = ent

        return best

    def get_attack_range(self) -> float:
        """Get the effective attack range (config override or from packet data)."""
        if self.config.attack_range > 0:
            return self.config.attack_range
        # Try to get from CharacterInfo of player entity
        ci = self.state.characters.get(self.state.player_entity_id)
        if ci and ci.attack_range > 0:
            return ci.attack_range
        # Fallback: use max attack range from any known character
        max_range = 0.0
        for ci in self.state.characters.values():
            if ci.attack_range > max_range:
                max_range = ci.attack_range
        return max_range if max_range > 0 else 800.0  # default fallback

    def is_in_range(self, entity: Entity) -> bool:
        """Check if an entity is within attack range."""
        dist = self.state.distance_to_player(entity.entity_id)
        if dist is None:
            return False
        return dist <= self.get_attack_range()

    # ---- Movement ----

    def angle_to_entity(self, entity: Entity) -> float:
        """Calculate angle from player to entity in radians."""
        dx = entity.x - self.state.player_x
        dy = entity.y - self.state.player_y
        return math.atan2(dy, dx)

    def move_toward(self, entity: Entity) -> None:
        """Click in the direction of the entity to walk toward it."""
        angle = self.angle_to_entity(entity)
        self.inp.click_direction(angle, self.config.move_click_radius)
        self._stats.move_commands += 1
        log.info(
            "move → eid=%d dist=%.0f angle=%.0f° player=(%d,%d) target=(%d,%d)",
            entity.entity_id,
            self.state.distance_to_player(entity.entity_id) or 0,
            math.degrees(angle),
            self.state.player_x, self.state.player_y,
            entity.x, entity.y,
        )

    # ---- Attack ----

    def attack(self) -> None:
        """Execute attack action."""
        if self.config.attack_mode == "ctrl_a":
            self.inp.attack_all()
        else:
            self.inp.auto_attack()
        self._last_attack = time.time()
        self._stats.attacks += 1
        log.debug("attack (mode=%s)", self.config.attack_mode)

    def try_skills(self) -> None:
        """Use skills from the rotation if off cooldown."""
        now = time.time()
        for slot, cooldown in self.config.skill_rotation:
            last = self._skill_cooldowns.get(slot, 0.0)
            if (now - last) >= cooldown:
                self.inp.use_skill(slot)
                self._skill_cooldowns[slot] = now
                self._stats.skills_used += 1
                log.debug("use_skill slot=%d", slot)
                time.sleep(0.1)  # brief delay between skills

    # ---- Decision loop ----

    def tick(self) -> BotState:
        """Run one decision tick. Returns current bot state."""
        if self._paused:
            return self.bot_state

        monster = self.find_nearest_monster()
        now = time.time()

        if monster is None:
            # No monsters — idle
            if self.bot_state != BotState.IDLE:
                log.info("no monsters, idling")
            self.bot_state = BotState.IDLE
            self._target_eid = 0
            return self.bot_state

        dist = self.state.distance_to_player(monster.entity_id)
        in_range = self.is_in_range(monster)

        if not in_range:
            # Need to move toward monster
            if self._target_eid != monster.entity_id:
                self._target_eid = monster.entity_id
                self._move_start = now
                log.info(
                    "new target eid=%d dist=%.0f, moving",
                    monster.entity_id, dist or 0,
                )

            # Check move timeout — re-evaluate if stuck
            if (now - self._move_start) > self.config.move_timeout:
                log.warning("move timeout, re-targeting")
                self._target_eid = 0
                return self.bot_state

            self.move_toward(monster)
            self.bot_state = BotState.MOVING
            return self.bot_state

        # In range — attack
        self._target_eid = monster.entity_id
        self.bot_state = BotState.ATTACKING

        # Press attack periodically
        if (now - self._last_attack) >= self.config.attack_interval:
            self.attack()

        # Try skill rotation
        if self.config.skill_rotation:
            self.try_skills()

        return self.bot_state

    def run(self) -> None:
        """Run the bot loop until stopped. Blocks."""
        self._running = True
        log.info("bot loop started (tick=%.1fs)", self.config.tick_interval)

        try:
            while self._running:
                self.tick()
                time.sleep(self.config.tick_interval)
        except KeyboardInterrupt:
            log.info("bot loop stopped by user")
        finally:
            self._running = False

    def stop(self) -> None:
        """Signal the bot loop to stop."""
        self._running = False

    def pause(self) -> None:
        """Pause the bot (stops acting but keeps tracking)."""
        self._paused = True
        log.info("bot paused")

    def resume(self) -> None:
        """Resume the bot."""
        self._paused = False
        log.info("bot resumed")

    @property
    def stats(self) -> BotStats:
        return self._stats

    def status_line(self) -> str:
        """One-line status for display."""
        monster = None
        if self._target_eid:
            monster = self.state.entities.get(self._target_eid)

        dist_str = "?"
        if monster:
            d = self.state.distance_to_player(monster.entity_id)
            dist_str = f"{d:.0f}" if d is not None else "?"

        n_monsters = sum(
            1 for e in self.state.entities.values()
            if e.entity_type == "monster"
        )

        parts = [
            f"[{self.bot_state.name}]",
            f"monsters={n_monsters}",
            f"range={self.get_attack_range():.0f}",
        ]
        if monster:
            parts.append(f"target={monster.entity_id} dist={dist_str}")
        parts.append(
            f"atk={self._stats.attacks} skills={self._stats.skills_used}"
        )
        if self._paused:
            parts.insert(0, "PAUSED")
        return " | ".join(parts)


@dataclass
class BotStats:
    """Counters for bot activity."""
    attacks: int = 0
    skills_used: int = 0
    monsters_killed: int = 0
    items_picked: int = 0
    move_commands: int = 0
