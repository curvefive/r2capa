/* SPDX-License-Identifier: Apache-2.0 */
#include "command.h"

#include <stddef.h>
#include <stdint.h>

enum {
  R2CAPA_MAX_HEX_ADDRESS_LENGTH = 18,     /* 0x plus 16 hexadecimal digits. */
  R2CAPA_MAX_DECIMAL_ADDRESS_LENGTH = 20, /* UINT64_MAX in base 10. */
};

static bool is_decimal_digit(char value) {
  return value >= '0' && value <= '9';
}

static bool is_hex_digit(char value) {
  return is_decimal_digit(value) || (value >= 'a' && value <= 'f') ||
         (value >= 'A' && value <= 'F');
}

static bool command_is(const char *input, const char *expected) {
  if (!input || !expected) {
    return false;
  }
  while (*expected) {
    if (*input != *expected) {
      return false;
    }
    input++;
    expected++;
  }
  return *input == '\0';
}

static bool command_starts_with(const char *input, const char *prefix) {
  if (!input || !prefix) {
    return false;
  }
  while (*prefix) {
    if (*input != *prefix) {
      return false;
    }
    input++;
    prefix++;
  }
  return true;
}

static bool valid_hex_address(const char *value) {
  size_t digits = 0;
  while (*value) {
    if (!is_hex_digit(*value) || ++digits > R2CAPA_MAX_HEX_ADDRESS_LENGTH - 2) {
      return false;
    }
    value++;
  }
  return digits > 0;
}

static bool valid_decimal_address(const char *value) {
  size_t digits = 0;
  uint64_t parsed = 0;
  while (*value) {
    if (!is_decimal_digit(*value) ||
        ++digits > R2CAPA_MAX_DECIMAL_ADDRESS_LENGTH) {
      return false;
    }
    uint64_t digit = (uint64_t)(*value - '0');
    if (parsed > (UINT64_MAX - digit) / 10) {
      return false;
    }
    parsed = (parsed * 10) + digit;
    value++;
  }
  return digits > 0;
}

static bool valid_address(const char *value) {
  if (!value || !*value) {
    return false;
  }
  if (command_starts_with(value, "0x")) {
    return valid_hex_address(value + 2);
  }
  return valid_decimal_address(value);
}

R2CapaParsedCommand r2capa_parse_command(const char *input) {
  R2CapaParsedCommand result = {R2CAPA_COMMAND_NOT_HANDLED, NULL};
  if (!command_starts_with(input, "r2capa")) {
    return result;
  }

  if (command_is(input, "r2capa")) {
    result.command = R2CAPA_COMMAND_RUN;
  } else if (command_is(input, "r2capa?")) {
    result.command = R2CAPA_COMMAND_HELP;
  } else if (command_is(input, "r2capaj")) {
    result.command = R2CAPA_COMMAND_JSON;
  } else if (command_is(input, "r2capav")) {
    result.command = R2CAPA_COMMAND_VERBOSE;
  } else if (command_is(input, "r2capavv")) {
    result.command = R2CAPA_COMMAND_VVERBOSE;
  } else if (command_is(input, "r2capaa")) {
    result.command = R2CAPA_COMMAND_ANALYZE;
  } else if (command_is(input, "r2capa*")) {
    result.command = R2CAPA_COMMAND_SCRIPT;
  } else if (command_is(input, "r2capafeaturesj")) {
    result.command = R2CAPA_COMMAND_FEATURES;
  } else if (command_is(input, "r2capaf")) {
    result.command = R2CAPA_COMMAND_CURRENT_FUNCTION;
  } else if (command_starts_with(input, "r2capaf ")) {
    const char *address = input + 8;
    while (*address == ' ') {
      address++;
    }
    if (valid_address(address)) {
      result.command = R2CAPA_COMMAND_FUNCTION;
      result.address = address;
    } else {
      result.command = R2CAPA_COMMAND_INVALID;
    }
  } else {
    result.command = R2CAPA_COMMAND_INVALID;
  }
  return result;
}
