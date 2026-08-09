/* SPDX-License-Identifier: Apache-2.0 */
#ifndef R2CAPA_COMMAND_H
#define R2CAPA_COMMAND_H

#include <stdbool.h>

typedef enum {
  R2CAPA_COMMAND_NOT_HANDLED = 0,
  R2CAPA_COMMAND_RUN,
  R2CAPA_COMMAND_HELP,
  R2CAPA_COMMAND_JSON,
  R2CAPA_COMMAND_VERBOSE,
  R2CAPA_COMMAND_VVERBOSE,
  R2CAPA_COMMAND_ANALYZE,
  R2CAPA_COMMAND_SCRIPT,
  R2CAPA_COMMAND_FEATURES,
  R2CAPA_COMMAND_CURRENT_FUNCTION,
  R2CAPA_COMMAND_FUNCTION,
  R2CAPA_COMMAND_INVALID,
} R2CapaCommand;

typedef struct {
  R2CapaCommand command;
  const char *address;
} R2CapaParsedCommand;

R2CapaParsedCommand r2capa_parse_command(const char *input);

#endif
