/*
 * daemonize.c
 * This example daemonizes a process, writes a few log messages,
 * sleeps 20 seconds and terminates afterwards.
 * https://stackoverflow.com/questions/17954432/creating-a-daemon-in-linux
 * TODO: proper logging
 * TODO: proper signal handler
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <syslog.h>
#include <dirent.h>
#include <errno.h>
#include <sys/inotify.h>

#define EVENT_SIZE  (sizeof (struct inotify_event))
#define EVENT_BUF_LEN     (1024 * (EVENT_SIZE + 16))

static void skeleton_daemon(){
  pid_t pid;

  /* Fork off the parent process */
  pid = fork();

  /* An error occurred */
  if (pid < 0){
    exit(EXIT_FAILURE);
  }

  /* Success: Let the parent terminate */
  if (pid > 0){
    exit(EXIT_SUCCESS);
  }

  /* On success: The child process becomes session leader */
  if (setsid() < 0){
    exit(EXIT_FAILURE);
  }

  /* Catch, ignore and handle signals */
  //TODO: Implement a working signal handler */
  signal(SIGCHLD, SIG_IGN);
  signal(SIGHUP, SIG_IGN);

  /* Fork off for the second time*/
  pid = fork();

  /* An error occurred */
  if (pid < 0){
    exit(EXIT_FAILURE);
  }

  /* Success: Let the parent terminate */
  if (pid > 0){
    exit(EXIT_SUCCESS);
  }

  /* Set new file permissions */
  umask(0);

  /* Change the working directory to the root directory */
  /* or another appropriated directory */
  chdir("/tmp");

  /* Close all open file descriptors */
  int x;
  for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
  {
    close (x);
  }

  /* Open the log file */
  openlog ("cryptodaemon", LOG_PID, LOG_DAEMON);
}

int main(){

  char *fujiPath = "/mnt/sd/DCIM/100_FUJI";
  int fd, wd, i, length;
  char buffer[EVENT_BUF_LEN];

  skeleton_daemon();
  //TODO: do we really need this block?
  syslog (LOG_NOTICE, "Check if DCIM/100_FUJI exists.");
  DIR *fuji = opendir(fujiPath);
  if (fuji){
    syslog(LOG_NOTICE, "DCIM/100_FUJI found. Continue execting.");
    closedir(fuji);
  }
  else if (ENOENT == errno){
    syslog(LOG_NOTICE, "DCIM/100_FUJI not found. Create it and continue execting.");
    mkdir(fujiPath, 0777);
  }
  else {
    syslog(LOG_ERR, "Error (%d) occured during checking DCIM/100_FUJI. Exiting", errno);
    exit(1);
  }

  // creating the INOTIFY instance
  fd = inotify_init();

  // checking for error
  if (fd < 0) {
    syslog(LOG_ERR, "Error (%d) occured setting up inotify. Exiting", errno);
    exit(1);
  }

  // adding the fujiPath directory into watch list.
  wd = inotify_add_watch(fd, fujiPath, IN_CREATE);

  while(1){
    i = 0;
    length = read(fd, buffer, EVENT_BUF_LEN); 

    // checking for error
    if (length < 0) {
      perror("read");
    }  

    // actually read return the list of change events happens. Here, read the change event one by one and process it accordingly.
    while (i < length) {
      struct inotify_event *event = (struct inotify_event *) &buffer[i];
      if (event->len) {
        //TODO: fork the cryptosd executable and encrypt the file
        //TODO: after encryption overwrite the file
        syslog(LOG_NOTICE, "New file %s created.", event->name);
      }
      i += EVENT_SIZE + event->len;
    }
  }

  // removing the “/tmp” directory from the watch list.
  inotify_rm_watch(fd, wd);

  // closing the INOTIFY instance
  close(fd);
  syslog (LOG_NOTICE, "First daemon terminated.");
  closelog();

  return EXIT_SUCCESS;
}
