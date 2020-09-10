all:		repoinit

clean:
		rm -f repoinit

repoinit:	repoinit.c
		gcc -O6 -Wall -g -o repoinit repoinit.c
