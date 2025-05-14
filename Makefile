# Compiler (use gcc explicitly if cc is not gcc or if you prefer)
# CC=gcc
CC=cc

PACKAGE=mqtt-sn-tools
VERSION=0.0.7

# Compiler Flags
CFLAGS=-g -Wall -DVERSION=$(VERSION)

# Linker Flags (e.g., -L/path/to/libs)
LDFLAGS=

# ---> ADDED LINE: Define Libraries to Link <---
LDLIBS = -lssl -lcrypto

INSTALL?=install
prefix=/usr/local

TARGETS=mqtt-sn-dump mqtt-sn-pub mqtt-sn-sub mqtt-sn-serial-bridge

.PHONY : all install uninstall clean dist test coverage


all: $(TARGETS)

# ---> MODIFIED LINE: Added $(LDLIBS) to the linking command <---
$(TARGETS): %: mqtt-sn.o %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o : %.c mqtt-sn.h
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGETS)
	$(INSTALL) -d "$(DESTDIR)$(prefix)/bin"
	$(INSTALL) -s $(TARGETS) "$(DESTDIR)$(prefix)/bin"

uninstall:
	@for target in $(TARGETS); do \
		cmd="rm -f $(DESTDIR)$(prefix)/bin/$$target"; \
		echo "$$cmd" && $$cmd; \
	done

clean:
	-rm -f *.o *.gcda *.gcno $(TARGETS)
	-rm -Rf coverage

dist:
	distdir='$(PACKAGE)-$(VERSION)'; mkdir $$distdir || exit 1; \
	list=`git ls-files`; for file in $$list; do \
		cp -pR $$file $$distdir || exit 1; \
	done; \
	tar -zcf $$distdir.tar.gz $$distdir; \
	rm -fr $$distdir

test: all
	@(which bundle > /dev/null) || (echo "Ruby Bundler is not installed"; exit -1)
	cd test && bundle install && bundle exec rake test

# Use gcc for coverage report - it works better than clang/llvm
coverage: CC=gcc
coverage: CFLAGS += --coverage
coverage: LDFLAGS += --coverage
coverage: clean test
	mkdir -p coverage
	lcov \
	--capture \
	--directory . \
	--no-external \
	--output coverage/lcov.info
	genhtml \
	--title 'MQTT-SN Tools' \
	--output-directory coverage \
	coverage/lcov.info