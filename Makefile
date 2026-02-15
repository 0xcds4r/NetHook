CXX = g++
CXXFLAGS = -Wall -Wextra -O2 -fPIC -std=c++17 -w
LDFLAGS = -shared -ldl -pthread

TARGET = nethook.so
SOURCE = main.cpp

all: clean $(TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

.PHONY: all clean
