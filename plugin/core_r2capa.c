/* SPDX-License-Identifier: Apache-2.0 */
#include <r_core.h>
#include <r_lib.h>

#include "command.h"

/* RPluginMeta predates const-correct string fields. Keep writable backing
 * arrays so -Wwrite-strings remains enabled without casting away const. */
static char plugin_name[] = "capa";
static char plugin_description[] =
    "Run capa against the active radare2 analysis";
static char plugin_license[] = "Apache-2.0";
static char plugin_author[] = "CurveFive / Mouse";

static void print_help(RCore *core) {
  r_cons_printf(core->cons,
                "Usage: r2capa[?jv*af]\n"
                " r2capa             run capa against the active analysis\n"
                " r2capaj            emit capa ResultDocument JSON\n"
                " r2capav            show verbose matches\n"
                " r2capavv           show the complete evidence tree\n"
                " r2capaf [address]  restrict analysis to a function\n"
                " r2capaa            run aaa, then capa\n"
                " r2capa*            emit an r2 flag script\n"
                " r2capafeaturesj    list extracted features as JSON\n"
                " r2capa?            show this help\n");
}

static bool run_worker(RCore *core, const char *arguments) {
  if (!core || !arguments) {
    return true;
  }
  char *command =
      r_str_newf("#!pipe r2capa%s%s", *arguments ? " " : "", arguments);
  if (!command) {
    R_LOG_ERROR("r2capa: failed to allocate worker command");
    return true;
  }
  r_core_cmd0(core, command);
  free(command);
  return true;
}

static bool r_cmd_capa_call(RCorePluginSession *session, const char *input) {
  RCore *core = session ? session->core : NULL;
  R2CapaParsedCommand parsed = r2capa_parse_command(input);
  if (!core || parsed.command == R2CAPA_COMMAND_NOT_HANDLED) {
    return false;
  }

  switch (parsed.command) {
  case R2CAPA_COMMAND_RUN:
    return run_worker(core, "");
  case R2CAPA_COMMAND_HELP:
    print_help(core);
    return true;
  case R2CAPA_COMMAND_JSON:
    return run_worker(core, "--json");
  case R2CAPA_COMMAND_VERBOSE:
    return run_worker(core, "--verbose");
  case R2CAPA_COMMAND_VVERBOSE:
    return run_worker(core, "--verbose --verbose");
  case R2CAPA_COMMAND_ANALYZE:
    return run_worker(core, "--analyze");
  case R2CAPA_COMMAND_SCRIPT:
    return run_worker(core, "--r2-script");
  case R2CAPA_COMMAND_FEATURES:
    return run_worker(core, "--features");
  case R2CAPA_COMMAND_CURRENT_FUNCTION: {
    char *arguments = r_str_newf("--function 0x%" PFMT64x, core->addr);
    if (!arguments) {
      R_LOG_ERROR("r2capa: failed to allocate function argument");
      return true;
    }
    bool result = run_worker(core, arguments);
    free(arguments);
    return result;
  }
  case R2CAPA_COMMAND_FUNCTION: {
    char *arguments = r_str_newf("--function %s", parsed.address);
    if (!arguments) {
      R_LOG_ERROR("r2capa: failed to allocate function argument");
      return true;
    }
    bool result = run_worker(core, arguments);
    free(arguments);
    return result;
  }
  case R2CAPA_COMMAND_INVALID:
    R_LOG_ERROR("r2capa: invalid command or function address");
    print_help(core);
    return true;
  case R2CAPA_COMMAND_NOT_HANDLED:
  default:
    return false;
  }
}

RCorePlugin r_core_plugin_capa = {
    .meta =
        {
            .name = plugin_name,
            .desc = plugin_description,
            .license = plugin_license,
            .author = plugin_author,
        },
    .call = r_cmd_capa_call,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_CORE,
    .data = &r_core_plugin_capa,
    .version = R2_VERSION,
};
#endif
