/*
 * @file cryptodaemon.c
 * @author stiefel40k
 * @date 05.07.2017
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
#include <syslog.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/wait.h>

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
  struct dirent *fujiContent;
  int sleepTime = 5;
  DIR *fuji;

  skeleton_daemon();
  // TODO: do we really need this block?
  // DCIM/100CANON for canon
  syslog (LOG_NOTICE, "Check if DCIM/100_FUJI exists.");
  fuji = opendir(fujiPath);
  if (fuji){
    syslog(LOG_NOTICE, "DCIM/100_FUJI found. Continue execting.");
    closedir(fuji);
  }
  else if (ENOENT == errno){
    syslog(LOG_NOTICE, "DCIM/100_FUJI not found. Create it and continue execting.");
    mkdir(fujiPath, 0777);
    // TODO: wait until found
  }
  else {
    syslog(LOG_ERR, "Error (%d) occured during checking DCIM/100_FUJI. Exiting", errno);
    exit(1);
  }

 while(1){

    fuji = opendir(fujiPath);
    // read the filelisting
    if (fuji){
      while ((fujiContent = readdir(fuji)) != NULL) {
        if (fujiContent->d_type == DT_REG) {
          syslog(LOG_NOTICE, "Beginning to handle %s", fujiContent->d_name);
          int pathLength = strlen(fujiContent->d_name) + strlen(fujiPath) + 1;
          char *newFilePath = (char *)malloc(pathLength);

          if(newFilePath == NULL){
            syslog(LOG_ERR, "Error during initializing newFilePath buffer. Continue without encrypting");
          }

          else {
            memset(newFilePath, '\0', pathLength);
            strncpy(newFilePath, fujiPath, strlen(fujiPath));
            strncat(newFilePath, fujiContent->d_name, strlen(fujiContent->d_name));

            if (strstr(fujiContent->d_name, ".out") == NULL){
              // new picture found
              pid_t childPid = fork();

              if (childPid == -1){
                // TODO: store the event name and try to encrypt later.
                syslog(LOG_ERR, "Error %d occured during start of cryptosd. Continuing without encrypting %s", errno, fujiContent->d_name);
              }
              else if(childPid == 0){
                // Child process
                // TODO: change path of key
                syslog(LOG_NOTICE, "Starting cryptosd for %s.", fujiContent->d_name);
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
                syslog(LOG_NOTICE, "Child (cryptosd) pid: %d", childPid);
                int returnStatus = 9;
                waitpid(childPid, &returnStatus, 0);
                if (returnStatus != 0){
                  syslog(LOG_ERR, "Child (cryptosd) returned with errorcode %d", returnStatus);
                  // TODO: check if encryption done or not
                }
                else {
                  syslog(LOG_NOTICE, "Encryption done for %s. Beginning with the deletion.", newFilePath);
                  // outfile found, delete the original one

                  pid_t childPid = fork();

                  if (childPid == -1){
                    syslog(LOG_ERR, "Error (%d) during start of rm. Continue without deleting %s", errno, fujiContent->d_name);
                  }
                  else if(childPid == 0){
                    // Child process
                    syslog(LOG_NOTICE, "Starting deletion of %s", fujiContent->d_name);
                    char *argList[] = {"rm",
                      newFilePath,
                      NULL
                    };
                    execvp("rm", argList);
                    syslog(LOG_ERR, "Error during execvp of rm for %s", fujiContent->d_name);
                    abort();
                  }
                  else {
                    syslog(LOG_NOTICE, "Child (rm) pid: %d", childPid);
                    returnStatus = 9;
                    waitpid(childPid, &returnStatus, 0);
                    if (returnStatus != 0){
                      syslog(LOG_ERR, "Child (rm) returned with errorcode %d", returnStatus);
                    }
                    else {
                      syslog(LOG_NOTICE, "Deletion done for %s", fujiContent->d_name);
                    }
                  }
                }
              }
            }
          }
        }
      }
      if (closedir(fuji) == -1){
        syslog(LOG_ERR, "Error during closing the directory %s", fujiPath);
        // TODO: try until you can close it or exit
      }
    }
    syslog(LOG_NOTICE, "Sleep %d seconds", sleepTime);
    sleep(sleepTime);
  }

  syslog (LOG_NOTICE, "Cryptodaemon terminated.");
  closelog();

  return EXIT_SUCCESS;
}