all:		repoinit splitimage

clean:
		rm -f repoinit
		rm -f splitimage

repoinit:	repoinit.c
		gcc -O6 -Wall -g -o repoinit repoinit.c

splitimage:	splitimage.c base64enc.c base64enc.h reposet.c reposet.h rw.h
		gcc -O6 -Wall -g -o splitimage splitimage.c base64enc.c reposet.c `libgcrypt-config --cflags --libs`
