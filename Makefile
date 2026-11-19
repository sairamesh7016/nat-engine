CC      := gcc
CFLAGS  := -std=gnu11 -O2 -Wall -Wextra -Werror -Iinclude -pthread
LDFLAGS := -pthread

SRC_DIR   := src
BUILD_DIR := build

ENGINE_SRCS := $(SRC_DIR)/main.c \
               $(SRC_DIR)/nat_ct.c \
               $(SRC_DIR)/nat_rewrite.c \
               $(SRC_DIR)/nat_state.c \
               $(SRC_DIR)/nat_frag.c \
               $(SRC_DIR)/nat_cli.c

CTL_SRCS    := $(SRC_DIR)/natctl_main.c \
               $(SRC_DIR)/nat_cli.c \
               $(SRC_DIR)/nat_ct.c \
               $(SRC_DIR)/nat_state.c

ENGINE_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(ENGINE_SRCS))
CTL_OBJS    := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(CTL_SRCS))

.PHONY: all clean dirs

all: dirs nat-engine natctl

dirs:
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

nat-engine: $(ENGINE_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

natctl: $(CTL_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR) nat-engine natctl
