"""Constants for the CUKTECH AD1204U Home Assistant integration."""

from __future__ import annotations

DOMAIN = "cuktech_ble"
MANUFACTURER = "CUKTECH"
MODEL = "AD1204U"
DEFAULT_DEVICE_NAME = "CUKTECH 10 GaN Charger Ultra"

CONF_BLUEZ_START_NOTIFY = "bluez_start_notify"
CONF_CONNECTION_TIMEOUT = "connection_timeout"
CONF_IDLE_RELEASE = "idle_release"
CONF_LOCAL_NAME = "local_name"
CONF_UPDATE_PERIOD = "update_period"

DEFAULT_CONNECTION_TIMEOUT = 15.0
DEFAULT_IDLE_RELEASE = 300.0
DEFAULT_UPDATE_PERIOD = 30.0
