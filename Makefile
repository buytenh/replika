all:		mkhashmap mkrand replika

clean:
		rm -f mkhashmap mkrand replika

mkhashmap:	mkhashmap.c common.c common.h
		gcc -Wall -o mkhashmap mkhashmap.c common.c `libgcrypt-config --cflags --libs` -lpthread

mkrand:		mkrand.c common.c common.h
		gcc -Wall -o mkrand mkrand.c common.c `libgcrypt-config --cflags --libs` -lpthread

replika:	replika.c common.c common.h
		gcc -Wall -o replika replika.c common.c `libgcrypt-config --cflags --libs` -lpthread
