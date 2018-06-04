CFLAGS       = -W -Wall

# include path to AVR library
INCLUDE_PATH = /usr/lib/avr/include
# splint static check
SPLINT       = splint test.c aes.c -I$(INCLUDE_PATH) +charindex -unrecog

timelock: timelock.o aes.o
	$(CC) $(CFLAGS) -o $@ $>

timelock.o: timelock.c aes.h

aes.o: aes.c aes.h

clean:
	rm -f timelock
	rm -f *.o *.gch *.out *.hex *.map

lint:
	$(call SPLINT)
