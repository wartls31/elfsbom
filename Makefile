XX      := g++

TARGET   := elf-sbom
SRC_PATH := src
BUILD_PATH := build

SOURCES  := $(shell find $(SRC_PATH) -name '*.cpp')
OBJECTS  := $(SOURCES:$(SRC_PATH)/%.cpp=$(BUILD_PATH)/%.o)
DEPS     := $(OBJECTS:.o=.d)

CXXFLAGS := -std=c++17 -O2 \
            -Wall -Wextra -Wpedantic -Werror \
            -fPIE
            
CPPFLAGS := $(shell pkg-config --cflags libelf libdw) -Isrc
LDFLAGS  := $(shell pkg-config --libs   libelf libdw)

.PHONY: all clean disp

all: $(TARGET)

disp:
	@echo "SOURCES: $(SOURCES)"
	@echo "OBJECTS: $(OBJECTS)"
	@echo "DEPS:    $(DEPS)"

-include $(DEPS)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_PATH)/%.o: $(SRC_PATH)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -MMD -MP -c -o $@ $<

clean:
	rm -rf $(BUILD_PATH) $(TARGET)