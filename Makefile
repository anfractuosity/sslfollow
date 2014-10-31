hellomake:
	gcc -I/usr/include/nspr -I/usr/include/nss -I/usr/include -I. -fPIC -D_GNU_SOURCE -shared follow.c -o follow.so 



