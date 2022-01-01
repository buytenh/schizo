all:		fsck gc init repomount scrub splitimage

clean:
		rm -f fsck
		rm -f gc
		rm -f init
		rm -f repomount
		rm -f scrub
		rm -f splitimage

fsck:		fsck.c base64dec.c base64dec.h base64enc.c base64enc.h enumerate_chunks.c enumerate_chunks.h enumerate_images.c enumerate_images.h enumerate_image_chunks.c enumerate_image_chunks.h reposet.c reposet.h rw.h threads.c threads.h
		gcc -O6 -Wall -g -o fsck -pthread fsck.c base64dec.c base64enc.c enumerate_chunks.c enumerate_images.c enumerate_image_chunks.c reposet.c threads.c `pkg-config ivykis --cflags --libs` `libgcrypt-config --cflags --libs`

gc:		gc.c base64dec.c base64dec.h base64enc.c base64enc.h enumerate_chunks.c enumerate_chunks.h enumerate_images.c enumerate_images.h enumerate_image_chunks.c enumerate_image_chunks.h reposet.c reposet.h rw.h threads.c threads.h
		gcc -O6 -Wall -g -o gc -pthread gc.c base64dec.c base64enc.c enumerate_chunks.c enumerate_images.c enumerate_image_chunks.c reposet.c threads.c `pkg-config ivykis --cflags --libs` `libgcrypt-config --cflags --libs`

init:		init.c
		gcc -O6 -Wall -g -o init init.c

repomount:	repomount.c base64enc.c base64enc.h reposet.c reposet.h rw.h
		gcc -O6 -Wall -g -o repomount repomount.c base64enc.c reposet.c `pkg-config fuse3 --cflags --libs` `pkg-config ivykis --cflags --libs` `libgcrypt-config --cflags --libs`

scrub:		scrub.c base64dec.c base64dec.h base64enc.c base64enc.h enumerate_chunks.c enumerate_chunks.h reposet.c reposet.h rw.h threads.c threads.h
		gcc -O6 -Wall -g -o scrub -pthread scrub.c base64dec.c base64enc.c enumerate_chunks.c reposet.c threads.c `libgcrypt-config --cflags --libs`

splitimage:	splitimage.c base64enc.c base64enc.h reposet.c reposet.h rw.h
		gcc -O6 -Wall -g -o splitimage splitimage.c base64enc.c reposet.c `libgcrypt-config --cflags --libs`
