all:		fsck repoinit repomount splitimage

clean:
		rm -f fsck
		rm -f repoinit
		rm -f repomount
		rm -f splitimage

fsck:		fsck.c base64enc.c base64enc.h reposet.c reposet.h rw.h
		gcc -O6 -Wall -g -o fsck fsck.c base64enc.c reposet.c `pkg-config ivykis --cflags --libs` `libgcrypt-config --cflags --libs`

repoinit:	repoinit.c
		gcc -O6 -Wall -g -o repoinit repoinit.c

repomount:	repomount.c base64enc.c base64enc.h reposet.c reposet.h rw.h
		gcc -O6 -Wall -g -o repomount repomount.c base64enc.c reposet.c `pkg-config fuse3 --cflags --libs` `pkg-config ivykis --cflags --libs` `libgcrypt-config --cflags --libs`

splitimage:	splitimage.c base64enc.c base64enc.h reposet.c reposet.h rw.h
		gcc -O6 -Wall -g -o splitimage splitimage.c base64enc.c reposet.c `libgcrypt-config --cflags --libs`
