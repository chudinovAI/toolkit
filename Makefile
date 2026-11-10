CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -Werror
TOOLS := cgwhy ns-diff alloc-bench cacheline-scout socket-bench pcap-pair pmtu-check
COMMANDS := $(addprefix bin/,$(TOOLS))
LIBRARIES := build/liballocaudit.so build/libsocketbench.so

.PHONY: all scripts native linux clean
all: scripts native
scripts: $(COMMANDS)
native: $(LIBRARIES)

linux:
	@test "$$(uname -s)" = Linux || { printf '%s\n' 'Native benchmark helpers require Linux. Use make scripts for offline tools.' >&2; exit 1; }

bin build:
	mkdir -p $@

bin/%: tools/%/main.py | bin
	chmod +x $<
	ln -sf ../$< $@

build/liballocaudit.so: tools/alloc-bench/allocaudit.c tools/_bench_evidence.h | build linux
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $<

build/libsocketbench.so: tools/socket-bench/socketbench.c tools/_bench_evidence.h | build linux
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -ldl -pthread

clean:
	rm -f $(COMMANDS) $(LIBRARIES)
