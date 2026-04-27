"""Select entities for enum-valued charger settings."""

from __future__ import annotations

from homeassistant.components.select import SelectEntity, SelectEntityDescription
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import AD1204UConfigEntry
from .coordinator import AD1204UCoordinator
from .entity import AD1204UEntity

# scene_mode enum reversed from Mi Home tablet capture 2026-04-23:
# 1 = AI Mode, 2 = Hybrid, 3 = Single, 4 = Dual.
SCENE_MODE_SIID = 2
SCENE_MODE_PIID = 0x0005
SCENE_MODE_BY_VALUE: dict[int, str] = {1: "ai_mode", 2: "hybrid", 3: "single", 4: "dual"}
SCENE_MODE_BY_KEY: dict[str, int] = {v: k for k, v in SCENE_MODE_BY_VALUE.items()}

# screen_save_time enum reversed from Mi Home tablet capture 2026-04-26:
# 1 = 1 Min, 5 = 5 Min, 10 = 10 Min, 30 = 30 Min, 0 = Always-On.
SCREEN_SAVE_TIME_SIID = 2
SCREEN_SAVE_TIME_PIID = 0x0006
SCREEN_SAVE_TIME_BY_VALUE: dict[int, str] = {1: "1_min", 5: "5_min", 10: "10_min", 30: "30_min", 0: "always_on"}
SCREEN_SAVE_TIME_BY_KEY: dict[str, int] = {v: k for k, v in SCREEN_SAVE_TIME_BY_VALUE.items()}

# device_language enum reversed from Mi Home tablet capture:
# 0 = English, 1 = Chinese.
DEVICE_LANGUAGE_SIID = 2
DEVICE_LANGUAGE_PIID = 0x000d
DEVICE_LANGUAGE_BY_VALUE: dict[int, str] = {0: "english", 1: "chinese"}
DEVICE_LANGUAGE_BY_KEY: dict[str, int] = {v: k for k, v in DEVICE_LANGUAGE_BY_VALUE.items()}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AD1204UConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data.coordinator
    async_add_entities([
        AD1204USceneModeSelect(coordinator),
        AD1204UScreenSaveTimeSelect(coordinator),
        AD1204UDeviceLanguageSelect(coordinator),
    ])


class AD1204USceneModeSelect(AD1204UEntity, SelectEntity):
    _attr_translation_key = "scene_mode"
    _attr_options = list(SCENE_MODE_BY_VALUE.values())

    def __init__(self, coordinator: AD1204UCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.address}_scene_mode"
        self.entity_description = SelectEntityDescription(
            key="scene_mode",
            translation_key="scene_mode",
        )

    @property
    def current_option(self) -> str | None:
        data = self.coordinator.data
        if data is None or data.scene_mode is None:
            return None
        return SCENE_MODE_BY_VALUE.get(data.scene_mode)

    async def async_select_option(self, option: str) -> None:
        value = SCENE_MODE_BY_KEY[option]
        await self.coordinator.async_set_property(
            SCENE_MODE_SIID, SCENE_MODE_PIID, value
        )

class AD1204UScreenSaveTimeSelect(AD1204UEntity, SelectEntity):
    _attr_translation_key = "screen_save_time"
    _attr_options = list(SCREEN_SAVE_TIME_BY_VALUE.values())

    def __init__(self, coordinator: AD1204UCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.address}_screen_save_time"
        self.entity_description = SelectEntityDescription(
            key="screen_save_time",
            translation_key="screen_save_time",
        )

    @property
    def current_option(self) -> str | None:
        data = self.coordinator.data
        if data is None or data.screen_save_time is None:
            return None
        return SCREEN_SAVE_TIME_BY_VALUE.get(data.screen_save_time)

    async def async_select_option(self, option: str) -> None:
        value = SCREEN_SAVE_TIME_BY_KEY[option]
        await self.coordinator.async_set_property(
            SCREEN_SAVE_TIME_SIID, SCREEN_SAVE_TIME_PIID, value
        )

class AD1204UDeviceLanguageSelect(AD1204UEntity, SelectEntity):
    _attr_translation_key = "device_language"
    _attr_options = list(DEVICE_LANGUAGE_BY_VALUE.values())

    def __init__(self, coordinator: AD1204UCoordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.address}_device_language"
        self.entity_description = SelectEntityDescription(
            key="device_language",
            translation_key="device_language",
        )

    @property
    def current_option(self) -> str | None:
        data = self.coordinator.data
        if data is None or data.device_language is None:
            return None
        return DEVICE_LANGUAGE_BY_VALUE.get(data.device_language)

    async def async_select_option(self, option: str) -> None:
        value = DEVICE_LANGUAGE_BY_KEY[option]
        await self.coordinator.async_set_property(
            DEVICE_LANGUAGE_SIID, DEVICE_LANGUAGE_PIID, value
        )
