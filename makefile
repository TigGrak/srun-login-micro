# --- 基础配置 ---
BUILD_DIR = build
TARGET_NAME = srun_crypto
TARGET = $(BUILD_DIR)/$(TARGET_NAME)
SRC = source/srun_crypto.c

# --- 编译器与参数逻辑 ---
CC ?= gcc

# 根据编译器名称判断是否开启静态编译
ifeq ($(CC), gcc)
    CFLAGS = -O3 -Wall -g
    MSG = "Building for Native (WSL/x86_64)..."
else
    CFLAGS = -O3 -s -Wall -static
    MSG = "Building with custom compiler: $(CC)"
endif


all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(TARGET): $(SRC)
	@echo $(MSG)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)
	@echo "Build successful: $(TARGET)"

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean