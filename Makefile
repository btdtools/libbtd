libbtd.so: libbtd.c
	gcc -shared -o $@ -g -fPIC -Wextra -Wall -Werror -pedantic -std=gnu11 $<

clean:
	$(RM) libbtd.so
