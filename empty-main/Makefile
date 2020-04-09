APP := app.out
OBJS := main.o

CC := gcc
LD := gcc

CFLAGS  := -std=c99 -O0 -g -Wall -Wextra -Werror
LDFLAGS := 

.PHONY: all clean

all: $(APP)

$(APP): $(OBJS)
	$(LD) $^ $(LDFLAGS) -o $@

clean:
	rm -f $(APP) $(OBJS)
