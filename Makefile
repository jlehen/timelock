CFLAGS       = -W -Wall

# include path to AVR library
INCLUDE_PATH = /usr/lib/avr/include
# splint static check
SPLINT       = splint test.c aes.c -I$(INCLUDE_PATH) +charindex -unrecog

seal: seal.o aes.o
	$(CC) $(CFLAGS) -o $@ $>

seal.o: seal.c aes.h

aes.o: aes.c aes.h

clean:
	rm -f seal
	rm -f *.o *.gch *.out *.hex *.map

lint:
	$(call SPLINT)
