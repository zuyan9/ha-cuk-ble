"""Constants for the Xiaomi Mi BLE standard-auth handshake.

These values come from the protocol spec at
https://github.com/dnandha/miauth/blob/master/doc/ble_security_proto.txt
"""

from __future__ import annotations

UPNP_UUID = "00000010-0000-1000-8000-00805f9b34fb"
AVDTP_UUID = "00000019-0000-1000-8000-00805f9b34fb"

# UPNP commands (host → device control channel)
CMD_GET_INFO = bytes.fromhex("a2 00 00 00")
CMD_SET_KEY = bytes.fromhex("15 00 00 00")
CMD_LOGIN = bytes.fromhex("24 00 00 00")
CMD_AUTH = bytes.fromhex("13 00 00 00")

# AVDTP parcel announcements (N-frames to follow) from host
CMD_SEND_DATA = bytes.fromhex("00 00 00 03 04 00")  # register: send our pub_key (4 frames)
CMD_SEND_DID = bytes.fromhex("00 00 00 00 02 00")  # register: send encrypted DID
CMD_SEND_KEY = bytes.fromhex("00 00 00 0b 01 00")  # login: send our 16-byte rand
CMD_SEND_INFO = bytes.fromhex("00 00 00 0a 02 00")  # login: send 32-byte HMAC

# AVDTP receive-side control frames
RCV_RDY = bytes.fromhex("00 00 01 01")
RCV_OK = bytes.fromhex("00 00 01 00")
RCV_TOUT = bytes.fromhex("00 00 01 05 01 00")
RCV_ERR = bytes.fromhex("00 00 01 05 03 00")

# Greeting (official variant): host triggers a challenge-echo handshake on
# AVDTP before CMD_LOGIN/CMD_GET_INFO. Seen in Mi Home's actual binding flow.
GREETING_TRIGGER = bytes.fromhex("a4")
# Ack for inline responses (00 00 02 XX + payload) — "got it, next please".
OFFICIAL_ACK = bytes.fromhex("00 00 03 00")

# Device announces it is about to send these parcels
RCV_RESP_KEY = bytes.fromhex("00 00 00 0d 01 00")  # login: device's 16-byte rand
RCV_RESP_INFO = bytes.fromhex("00 00 00 0c 02 00")  # login: device's 32-byte HMAC
RCV_WR_DID = bytes.fromhex("00 00 00 00 02 00")  # register: device info (20 bytes)
RCV_RESP_DATA = bytes.fromhex("00 00 00 03 04 00")  # register: device pub_key

# UPNP confirmations (device → host)
CFM_REGISTER_OK = bytes.fromhex("11 00 00 00")
CFM_REGISTER_ERR = bytes.fromhex("12 00 00 00")
CFM_LOGIN_OK = bytes.fromhex("21 00 00 00")
CFM_LOGIN_ERR = bytes.fromhex("23 00 00 00")

AUTH_ERRORS = {
    bytes.fromhex("e0 00 00 00"),
    bytes.fromhex("e1 00 00 00"),
    bytes.fromhex("e2 00 00 00"),
    bytes.fromhex("e3 00 00 00"),
}

# Parcel framing: 2-byte LE frame index + up to 18 bytes payload.
PARCEL_CHUNK_SIZE = 18
