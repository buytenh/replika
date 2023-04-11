all:		dedup efes mkhashmap mkrand replika uniques

clean:
		rm -f dedup efes mkhashmap mkrand replika uniques

dedup:		dedup.c dedup.h dedup_scan.c common.c common.h extents.c extents.h
		gcc -Wall -o dedup dedup.c dedup_scan.c common.c extents.c `libgcrypt-config --cflags --libs` `pkg-config --cflags --libs ivykis` -lpthread

efes:		efes.c common.c common.h
		gcc -Wall -o efes efes.c common.c `pkg-config fuse3 --cflags --libs` `libgcrypt-config --cflags --libs` -lpthread

mkhashmap:	mkhashmap.c common.c common.h
		gcc -Wall -o mkhashmap mkhashmap.c common.c `libgcrypt-config --cflags --libs` -lpthread

mkrand:		mkrand.c common.c common.h
		gcc -Wall -o mkrand mkrand.c common.c `libgcrypt-config --cflags --libs` -lpthread

replika:	replika.c common.c common.h
		gcc -Wall -o replika replika.c common.c `libgcrypt-config --cflags --libs` -lpthread

uniques:	uniques.c
		gcc -Wall -o uniques uniques.c `pkg-config --cflags --libs ivykis`
