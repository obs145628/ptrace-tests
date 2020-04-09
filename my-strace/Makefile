APP := mystrace
OBJS := main.o

CXX := g++
LD := g++

CXXFLAGS  := -std=c++17 -O0 -g -Wall -Wextra -Werror
LDFLAGS := 

.PHONY: all clean

all: $(APP)

$(APP): $(OBJS)
	$(LD) $^ $(LDFLAGS) -o $@

clean:
	rm -f $(APP) $(OBJS)
