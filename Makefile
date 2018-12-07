CC      := gcc
CFLAGS  := -O2 -Wall -Wno-deprecated-declarations
LDFLAGS :=
LIBS    := -lcurl -larchive

SRC:=$(wildcard *.c)

TARGET := hawker

OBJ := $(patsubst %.c, %.o, \
		$(filter %.c, $(SRC)))

all: $(TARGET)

%.o: %.c
	@echo "$@ <- $<"
	@$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): $(OBJ)
	@echo "Linking...[$(TARGET) <- $<]"
	@$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LIBS)

clean:
	@rm -f $(OBJ) $(TARGET) 

handin:
	@if [ -z "$(MY_NAME)" ]; then \
		echo "You did not provide your name, so I cannot handin."; \
		echo "try:"; \
	    echo "[you@you] MY_NAME=foo make handin"; exit 2; \
	 else true; fi
	@tar cvJf p4-$(MY_NAME)-handin.txz Makefile *.c *.h setup.sh


.PHONY: all clean
