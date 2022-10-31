all:		repomount schizo

clean:
		rm -f repomount
		rm -f schizo

repomount:	repomount.c base64enc.c base64enc.h reposet.c reposet.h rw.h
		gcc -O6 -Wall -g -o repomount repomount.c base64enc.c reposet.c `pkg-config fuse3 --cflags --libs` `pkg-config ivykis --cflags --libs` `libgcrypt-config --cflags --libs`

schizo:		schizo.c base64dec.c base64dec.h base64enc.c base64enc.h cp_splitimage.c enumerate_chunks.c enumerate_chunks.h enumerate_images.c enumerate_images.h enumerate_image_chunks.c enumerate_image_chunks.h fsck.c gc.c init.c reposet.c reposet.h rw.h schizo.h scrub.c threads.c threads.h
		gcc -O6 -Wall -g -o schizo -pthread schizo.c base64dec.c base64enc.c cp_splitimage.c enumerate_chunks.c enumerate_images.c enumerate_image_chunks.c fsck.c gc.c init.c reposet.c scrub.c threads.c `pkg-config ivykis --cflags --libs` `libgcrypt-config --cflags --libs`
