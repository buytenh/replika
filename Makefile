all:		dedup efes mkhashmap mkhashmapref mkrand mktrimmap replika uniques

clean:
		rm -f dedup efes mkhashmap mkhashmapref mkrand mktrimmap replika uniques

dedup:		dedup.c dedup.h dedup_scan.c common.c common.h extents.c extents.h
		gcc -Wall -o dedup dedup.c dedup_scan.c common.c extents.c `libgcrypt-config --cflags --libs` `pkg-config --cflags --libs ivykis` -lpthread

efes:		efes.c common.c common.h
		gcc -Wall -o efes efes.c common.c `pkg-config fuse --cflags --libs` `libgcrypt-config --cflags --libs` -lpthread

mkhashmap:	mkhashmap.c common.c common.h
		gcc -Wall -o mkhashmap mkhashmap.c common.c `libgcrypt-config --cflags --libs` -lpthread

mkhashmapref:	mkhashmapref.c common.c common.h extents.c extents.h
		gcc -Wall -o mkhashmapref mkhashmapref.c common.c extents.c `libgcrypt-config --cflags --libs` `pkg-config --cflags --libs ivykis` -lpthread

mkrand:		mkrand.c common.c common.h
		gcc -Wall -o mkrand mkrand.c common.c `libgcrypt-config --cflags --libs` -lpthread

mktrimmap:	mktrimmap.c common.c common.h
		gcc -Wall -o mktrimmap mktrimmap.c common.c `libgcrypt-config --cflags --libs` -lpthread

replika:	replika.c common.c common.h
		gcc -Wall -o replika replika.c common.c `libgcrypt-config --cflags --libs` -lpthread

uniques:	uniques.c
		gcc -Wall -o uniques uniques.c `pkg-config --cflags --libs ivykis`
