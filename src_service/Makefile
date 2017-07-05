cryptodaemon_with_inotify.o:
	gcc -o cryptodaemon_with_inotify.o cryptodaemon_with_inotify.c

cryptodaemon_with_inotify_arm.o:
	@cc -s -static -O3 -o cryptodaemon_with_inotify_arm.o cryptodaemon_with_inotify.c
	chown 1000:1000 cryptodaemon_without_inotify.o

cryptodaemon_without_inotify.o:
	gcc -o cryptodaemon_without_inotify.o cryptodaemon_without_inotify.c

cryptodaemon_without_inotify_arm.o:
	@cc -s -static -O3 -o cryptodaemon_without_inotify_arm.o cryptodaemon_without_inotify.c
	chown 1000:1000 cryptodaemon_without_inotify_arm.o

.PHONY: clean
clean:
	rm *.o
