/* SPDX-License-Identifier: Apache-2.0 */
#include "command.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>

static void expect_command(const char *input, R2CapaCommand expected) {
  R2CapaParsedCommand parsed = r2capa_parse_command(input);
  assert(parsed.command == expected);
}

int main(void) {
  expect_command(NULL, R2CAPA_COMMAND_NOT_HANDLED);
  expect_command("pdf", R2CAPA_COMMAND_NOT_HANDLED);
  expect_command("capa", R2CAPA_COMMAND_NOT_HANDLED);
  expect_command("r2capa", R2CAPA_COMMAND_RUN);
  expect_command("r2capa?", R2CAPA_COMMAND_HELP);
  expect_command("r2capaj", R2CAPA_COMMAND_JSON);
  expect_command("r2capav", R2CAPA_COMMAND_VERBOSE);
  expect_command("r2capavv", R2CAPA_COMMAND_VVERBOSE);
  expect_command("r2capaa", R2CAPA_COMMAND_ANALYZE);
  expect_command("r2capa*", R2CAPA_COMMAND_SCRIPT);
  expect_command("r2capafeaturesj", R2CAPA_COMMAND_FEATURES);
  expect_command("r2capaf", R2CAPA_COMMAND_CURRENT_FUNCTION);

  R2CapaParsedCommand parsed = r2capa_parse_command("r2capaf   0x401000");
  assert(parsed.command == R2CAPA_COMMAND_FUNCTION);
  assert(parsed.address != NULL);
  assert(strcmp(parsed.address, "0x401000") == 0);

  expect_command("r2capaf -1", R2CAPA_COMMAND_INVALID);
  expect_command("r2capaf 0x", R2CAPA_COMMAND_INVALID);
  expect_command("r2capaf 0x401000;!sh", R2CAPA_COMMAND_INVALID);
  expect_command("r2capaf 0x401000 trailing", R2CAPA_COMMAND_INVALID);
  expect_command("r2capaf 18446744073709551615", R2CAPA_COMMAND_FUNCTION);
  expect_command("r2capaf 99999999999999999999", R2CAPA_COMMAND_INVALID);
  expect_command("r2capaf 184467440737095516150", R2CAPA_COMMAND_INVALID);
  expect_command("r2capaf 0xffffffffffffffff", R2CAPA_COMMAND_FUNCTION);
  expect_command("r2capaf 0x1ffffffffffffffff", R2CAPA_COMMAND_INVALID);
  expect_command("r2capaanything", R2CAPA_COMMAND_INVALID);

  char oversized[4096];
  memset(oversized, '1', sizeof(oversized));
  memcpy(oversized, "r2capaf ", 8);
  oversized[sizeof(oversized) - 1] = '\0';
  expect_command(oversized, R2CAPA_COMMAND_INVALID);

  return 0;
}
