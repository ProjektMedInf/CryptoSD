/*
 * @file cryptodaemon.c
 * @author stiefel40k
 * @date 21.06.2017
 *
 * @brief This is the daemon which is started through init, and handles the encryption of new files.
 * https://stackoverflow.com/questions/17954432/creating-a-daemon-in-linux
 * TODO: proper logging
 * TODO: proper signal handler
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <dirent.h>
#include <errno.h>
#include <sys/inotify.h>
#include <sys/wait.h>

#define EVENT_SIZE  (sizeof (struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

/*
 * Puts the program into daemon mode
 */
static void skeleton_daemon(void){
  pid_t pid;

  // Fork off the parent process
  pid = fork();

  // An error occurred
  if (pid < 0){
    exit(EXIT_FAILURE);
  }

  // Success: Let the parent terminate
  if (pid > 0){
    exit(EXIT_SUCCESS);
  }

  // On success: The child process becomes session leader
  if (setsid() < 0){
    exit(EXIT_FAILURE);
  }

  // Catch, ignore and handle signals
  // TODO: Implement a working signal handler
  signal(SIGCHLD, SIG_IGN);
  signal(SIGHUP, SIG_IGN);

  // Fork off for the second time
  pid = fork();

  // An error occurred
  if (pid < 0){
    exit(EXIT_FAILURE);
  }

  // Success: Let the parent terminate
  if (pid > 0){
    exit(EXIT_SUCCESS);
  }

  // Set new file permissions
  umask(0);

  // Change the working directory to the root directory
  // or another appropriated directory
  chdir("/tmp");

  // Close all open file descriptors
  int x;
  for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
  {
    close (x);
  }

  // Open the log file
  openlog ("cryptodaemon", LOG_PID, LOG_DAEMON);
}

/*
 * Main program of the daemon. Starts the deamonizing and starts cryptosd if a new file if found.
 * @returns 0 if no error happend and 1 if an error occured.
 */
int main(void){

  char *fujiPath = "/mnt/sd/DCIM/100_FUJI/";
  int fd, wd, i, length;
  char buffer[EVENT_BUF_LEN];

  skeleton_daemon();
  // TODO: do we really need this block?
  // DCIM/100CANON for canon
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
        syslog(LOG_NOTICE, "New file %s created.", event->name);
        int pathLength = strlen(event->name) + strlen(fujiPath) + 1;
        char *newFilePath = (char *)malloc(pathLength);

        if(newFilePath == NULL){
          syslog(LOG_ERR, "Error during initializing newFilePath buffer. Continue without encrypting");
        }

        else {
          memset(newFilePath, '\0', pathLength);
          strncpy(newFilePath, fujiPath, strlen(fujiPath));
          strncat(newFilePath, event->name, strlen(event->name));

          if (strstr(event->name, ".out") == NULL){
            // new picture found
            pid_t childPid = fork();

            if (childPid == -1){
              // TODO: store the event name and try to encrypt later.
              syslog(LOG_ERR, "Error %d occured during start of cryptosd. Continuing without encrypting %s", errno, event->name);
            }
            else if(childPid == 0){
              // Child process
              // TODO: change path of key
              syslog(LOG_NOTICE, "Starting cryptosd for %s.", event->name);
              char *argList[] = {"cryptosd",
                "-e",
                "-k",
                "/tmp/key",
                "-i",
                newFilePath,
                NULL
              };

              execvp("/tmp/cryptosd", argList);

              // only occures if an error happened
              syslog(LOG_ERR, "Error (%d) during execvp of cryptosd for %s.", newFilePath, errno);
              abort();
            }
            else {
              syslog(LOG_NOTICE, "Child pid: %d", childPid);
              int returnStatus;
              waitpid(childPid, &returnStatus, 0);
              if (returnStatus != 0){
                syslog(LOG_ERR, "Child returned with errorcode %d", returnStatus);
                // TODO: check if encryption done or not
              }
              else {
                syslog(LOG_NOTICE, "Encryption done for %s", newFilePath);
              }
            }
          }
          else {
            // outfile found, delete the original one
            char *origiPath = strndup(newFilePath, strlen(newFilePath) - 4);

            // TODO: add to global list and try delete later
            if(origiPath == NULL){
              syslog(LOG_ERR, "Error during initializing origiPath buffer. Continue without deleting %s (without .out)", event->name);
            }

            else {
              pid_t childPid = fork();

              if (childPid == -1){
                syslog(LOG_ERR, "Error (%d) during start of shred. Continue without deleting %s", errno, origiPath);
              }
              else if(childPid == 0){
                // Child process
                syslog(LOG_NOTICE, "Starting deletion of %s", origiPath);
                char *argList[] = {"rm",
                  origiPath,
                  NULL
                };
                execvp("rm", argList);
                syslog(LOG_ERR, "Error during execvp of rm for %s", origiPath);
                abort();
              }
              else {
                syslog(LOG_NOTICE, "Child pid: %d", childPid);
                int returnStatus;
                waitpid(childPid, &returnStatus, 0);
                if (returnStatus != 0){
                  syslog(LOG_ERR, "Child returned with errorcode %d", returnStatus);
                }
                else {
                  syslog(LOG_NOTICE, "Deletion done for %s", origiPath);
                }
              }
            }
          }
        }
        i += EVENT_SIZE + event->len;
      }
    }
  }
  inotify_rm_watch(fd, wd);

  // closing the INOTIFY instance
  close(fd);
  syslog (LOG_NOTICE, "Cryptodaemon terminated.");
  closelog();

  return EXIT_SUCCESS;
}
