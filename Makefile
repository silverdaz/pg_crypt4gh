# Makefile to build the pg_amqp extension

EXTENSION = pg_crypt4gh

DATA_built = $(EXTENSION)--1.0.sql
DATA = $(wildcard $(EXTENSION)--*--*.sql)

# compilation configuration
MODULE_big = $(EXTENSION)
OBJS = $(patsubst %.c,%.o,$(wildcard src/*.c))

#PG_CFLAGS = -std=gnu18

#PG_CPPFLAGS += -Wall -Wextra -Werror -Wno-unused-parameter -Wno-maybe-uninitialized -Wno-implicit-fallthrough 
PG_CPPFLAGS += -Isrc -I$(libpq_srcdir) $(shell pkg-config --cflags libsodium)
SHLIB_LINK = $(libpq) $(shell pkg-config --libs libsodium)
#EXTRA_CLEAN += $(addprefix src/,*.gcno *.gcda) # clean up after profiling runs

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

$(EXTENSION)--1.0.sql: $(EXTENSION).sql
	cat $^ > $@
