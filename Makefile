all:		efes mkhashmap mkrand replika uniques

clean:
		rm -f efes mkhashmap mkrand replika uniques

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
