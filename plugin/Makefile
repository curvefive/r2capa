CC ?= cc
R2 ?= r2
PKG_CONFIG ?= pkg-config
SO_EXT ?= $(shell $(R2) -H R2_LIBEXT 2>/dev/null || echo so)
TARGET := core_r2capa.$(SO_EXT)
C_STANDARD := -std=c11
WARNINGS := -Wall -Wextra -Werror -Wformat=2 -Wshadow -Wstrict-prototypes -Wwrite-strings
HARDENING := -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2
CFLAGS += $(C_STANDARD) $(WARNINGS) $(HARDENING) -fPIC $(shell $(PKG_CONFIG) --cflags r_core)
LDFLAGS += -shared $(shell $(PKG_CONFIG) --libs r_core)
PLUGIN_DIR ?= $(shell $(R2) -H R2_USER_PLUGINS)
TEST_TARGET := test_command
SANITIZERS ?= -fsanitize=address,undefined -fno-omit-frame-pointer
ANALYZER_FLAGS ?= -fanalyzer
ANALYSIS_OBJECTS := core_r2capa.analyze.o command.analyze.o

.PHONY: all analyze clean install parser-test uninstall

all: $(TARGET)

$(TARGET): core_r2capa.c command.c command.h
	$(CC) $(CFLAGS) core_r2capa.c command.c -o $@ $(LDFLAGS)

$(TEST_TARGET): command.c command.h test_command.c
	$(CC) $(C_STANDARD) $(WARNINGS) $(SANITIZERS) command.c test_command.c -o $@

parser-test: $(TEST_TARGET)
	./$(TEST_TARGET)
	$(RM) $(TEST_TARGET)

analyze:
	$(CC) $(CFLAGS) $(ANALYZER_FLAGS) -c core_r2capa.c -o core_r2capa.analyze.o
	$(CC) $(CFLAGS) $(ANALYZER_FLAGS) -c command.c -o command.analyze.o
	$(RM) $(ANALYSIS_OBJECTS)

install: $(TARGET)
	install -d "$(PLUGIN_DIR)"
	install -m 755 "$(TARGET)" "$(PLUGIN_DIR)/$(TARGET)"

uninstall:
	rm -f "$(PLUGIN_DIR)/$(TARGET)"

clean:
	$(RM) core_r2capa.so core_r2capa.dylib core_r2capa.dll $(TEST_TARGET) $(ANALYSIS_OBJECTS)
