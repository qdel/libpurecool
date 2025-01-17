"""Utilities for Dyson Pure Hot+Cool link devices."""
import json
import base64
from Crypto.Cipher import AES
from .const import DYSON_PURE_HOT_COOL_LINK_TOUR, \
    DYSON_360_EYE, DYSON_PURE_COOL, DYSON_PURE_COOL_DESKTOP, \
    DYSON_PURE_HOT_COOL, DYSON_PURE_COOL_HUMIDIFY


def support_heating(product_type):
    """Return True if device_model support heating mode, else False.

    :param product_type Dyson device model
    """
    if product_type in [DYSON_PURE_HOT_COOL_LINK_TOUR]:
        return True
    return False


def support_heating_v2(product_type):
    """Return True if v2 device_model support heating mode, else False.

    :param product_type Dyson device model
    """
    if product_type in [DYSON_PURE_HOT_COOL]:
        return True
    return False


def is_pure_cool_v2(product_type):
    """Return True if it is a v2 dyson pure cool device.

    :param product_type Dyson device model
    """
    if product_type in [DYSON_PURE_COOL, DYSON_PURE_COOL_DESKTOP,
                        DYSON_PURE_HOT_COOL, DYSON_PURE_COOL_HUMIDIFY]:
        return True
    return False

def is_pure_humidifycool_v2(product_type):
    """Return True if it is a v2 dyson pure humidify+cool device.

    :param product_type Dyson device model
    """
    if product_type == DYSON_PURE_COOL_HUMIDIFY:
        return True
    return False

def is_pure_humidifycool_v2(product_type):
    """Return True if it is a v2 dyson pure humidify+cool device.

    :param product_type Dyson device model
    """
    if product_type == DYSON_PURE_COOL_HUMIDIFY:
        return True
    return False


def is_heating_device(json_payload):
    """Return true if this json payload is a hot+cool device."""
    if json_payload['ProductType'] in [DYSON_PURE_HOT_COOL_LINK_TOUR]:
        return True
    return False


def is_heating_device_v2(json_payload):
    """Return true if this json payload is a v2 hot+cool device."""
    if json_payload['ProductType'] in [DYSON_PURE_HOT_COOL]:
        return True
    return False


def printable_fields(fields):
    """Return printable fields.

    :param fields list of tuble with (label, vallue)
    """
    for field in fields:
        yield field[0]+"="+field[1]


def unpad(string):
    """Un pad string."""
    return string[:-ord(string[len(string) - 1:])]


def decrypt_password(encrypted_password):
    """Decrypt password.

    :param encrypted_password: Encrypted password
    """
    key = b'\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10' \
          b'\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f '
    init_vector = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
                  b'\x00\x00\x00\x00'
    cipher = AES.new(key, AES.MODE_CBC, init_vector)
    json_password = json.loads(unpad(
        cipher.decrypt(base64.b64decode(encrypted_password)).decode('utf-8')))
    return json_password["apPasswordHash"]


def is_360_eye_device(json_payload):
    """Return true if this json payload is a Dyson 360 Eye device."""
    if json_payload['ProductType'] == DYSON_360_EYE:
        return True
    return False


def is_dyson_pure_cool_device(json_payload):
    """Return true if this json payload is a v2 dyson pure cool device."""
    if json_payload['ProductType'] in [DYSON_PURE_COOL,
                                       DYSON_PURE_COOL_DESKTOP]:
        return True
    return False

def is_dyson_pure_humidifycool_device(json_payload):
    """Return true if this json payload is a v2 dyson pure humidify+cool device."""
    if json_payload['ProductType'] == DYSON_PURE_COOL_HUMIDIFY:
        return True
    return False

def get_field_value(state, field):
    """Get field value."""
    return state[field][1] if isinstance(state[field], list) else state[
        field]
