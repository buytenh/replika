all:		dedup mkhashmap mkhashmapref mkrand replika

clean:
		rm -f dedup mkhashmap mkhashmapref mkrand replika

dedup:		dedup.c common.c common.h
		gcc -Wall -o dedup dedup.c common.c `libgcrypt-config --cflags --libs` `pkg-config --cflags --libs ivykis` -lpthread

mkhashmap:	mkhashmap.c common.c common.h
		gcc -Wall -o mkhashmap mkhashmap.c common.c `libgcrypt-config --cflags --libs` -lpthread

mkhashmapref:	mkhashmapref.c common.c common.h extents.c extents.h
		gcc -Wall -o mkhashmapref mkhashmapref.c common.c extents.c `libgcrypt-config --cflags --libs` `pkg-config --cflags --libs ivykis` -lpthread

mkrand:		mkrand.c common.c common.h
		gcc -Wall -o mkrand mkrand.c common.c `libgcrypt-config --cflags --libs` -lpthread

replika:	replika.c common.c common.h
		gcc -Wall -o replika replika.c common.c `libgcrypt-config --cflags --libs` -lpthread
