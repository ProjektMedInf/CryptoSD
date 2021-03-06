/**
 * @file cryptodaemon_without_inotify.c
 * @author stiefel40k
 * @date 05.07.2017
 *
 * @brief This is the daemon which is started through init, and handles the encryption of new files.
 */
 // https://stackoverflow.com/questions/17954432/creating-a-daemon-in-linux
 // TODO: proper signal handler


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/mount.h>

/**
 * Returns the directories inside a specific directory
 *
 * @param path path where the method should search
 * @param ls array which holds the found directories
 * @return the number of found directories
 */
size_t getDCIMDirectories(const char * path, char * * * ls) {
  size_t numberOfDirectories = 0;
  size_t length = 0;
  DIR * dp = NULL;
  struct dirent * ep = NULL;

  dp = opendir(path);
  if (NULL == dp) {
    fprintf(stderr, "no such directory: '%s'", path);
    return 0;
  }

  * ls = NULL;
  ep = readdir(dp);
  while (NULL != ep) {
    if (strcmp(strdup(ep -> d_name), ".") != 0) {
      if (strcmp(strdup(ep -> d_name), "..") != 0) {
        numberOfDirectories++;
      }
    }
    ep = readdir(dp);
  }

  rewinddir(dp); * ls = calloc(numberOfDirectories, sizeof(char * ));

  numberOfDirectories = 0;
  ep = readdir(dp);
  while (NULL != ep) {
    if (strcmp(strdup(ep -> d_name), ".") != 0) {
      if (strcmp(strdup(ep -> d_name), "..") != 0) {
        ( * ls)[numberOfDirectories++] = strdup(ep -> d_name);
        syslog(LOG_NOTICE, "Directory %s exists.", strdup(ep -> d_name));
      }
    }
    ep = readdir(dp);
  }

  closedir(dp);
  return numberOfDirectories;
}

/**
 * Checks if the directory can be opened. If it doesn't exist it creates it
 * 
 * @param imagePath path to the directory
 */
void checkDirectory(const char * imagePath) {
  DIR * imageDir;
  syslog(LOG_NOTICE, "Check if %s exists.", imagePath);
  imageDir = opendir(imagePath);
  if (imageDir) {
    syslog(LOG_NOTICE, "%s found. Continue execting.", imagePath);
    closedir(imageDir);
  } else if (ENOENT == errno) {
    syslog(LOG_NOTICE, "%s not found. Create it and continue execting.", imagePath);
    mkdir(imagePath, 0777);
    // TODO: wait until found
  } else {
    syslog(LOG_ERR, "Error (%d) occured during checking %s. Exiting", errno, imagePath);
    exit(1);
  }
}

/**
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
  //signal(SIGCHLD, SIG_IGN);
  //signal(SIGHUP, SIG_IGN);

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
  chdir("/");

  // Close all open file descriptors
  int x;
  for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
  {
    close (x);
  }

  // Open the log file
  openlog ("cryptodaemon", LOG_PID, LOG_DAEMON);
}

/**
 * Main program of the daemon. Starts the deamonizing and starts cryptosd if a new file if found.
 * @returns 0 if no error happend and 1 if an error occured.
 */
int main(void){

  skeleton_daemon();

  while(1){

    char * * DCIMDirectories;
    size_t numberOfDirectories;
    int i;

    numberOfDirectories = getDCIMDirectories("/mnt/sd/DCIM/", &DCIMDirectories);
    for (i = 0; i <numberOfDirectories; i++) {

      char imagePath [100];
      imagePath[0] = 0;
      strcat(imagePath, "/mnt/sd/DCIM/");
      strcat(imagePath, DCIMDirectories[i]);
      strcat(imagePath, "/");
      checkDirectory(imagePath);
      DIR *imageDir;
      imageDir = opendir(imagePath);
      struct dirent *imageDirContent;

      // read the filelisting
      if (imageDir) {
        while ((imageDirContent = readdir(imageDir)) != NULL) {
          if (imageDirContent->d_type == DT_REG) {
            int pathLength = strlen(imageDirContent->d_name) + strlen(imagePath) + 1;
            char *newFilePath = (char *)malloc(pathLength);

            if(newFilePath == NULL){
              syslog(LOG_ERR, "Error during initializing newFilePath buffer. Continue without encrypting");
            }

            else {
              memset(newFilePath, '\0', pathLength);
              strncpy(newFilePath, imagePath, strlen(imagePath));
              strncat(newFilePath, imageDirContent->d_name, strlen(imageDirContent->d_name));

              if (strstr(imageDirContent->d_name, ".out") == NULL){
                syslog(LOG_NOTICE, "Beginning to handle %s", imageDirContent->d_name);
                // new picture found
                pid_t childPid = fork();

                if (childPid == -1){
                  syslog(LOG_ERR, "Error %d occured during start of cryptosd. Continuing without encrypting %s", errno, imageDirContent->d_name);
                }
                else if(childPid == 0){
                  // Child process
                  syslog(LOG_NOTICE, "Starting cryptosd for %s.", imageDirContent->d_name);
                  char *argList[] = {"cryptosd",
                    "-e",
                    "-p",
                    "/mnt/sd/key",
                    "-i",
                    newFilePath,
                    NULL
                  };

                  execvp("/etc/cryptosd", argList);

                  // only occures if an error happened
                  syslog(LOG_ERR, "Error (%d) during execvp of cryptosd for %s.", errno, newFilePath);
                  abort();
                }
                else {
                  syslog(LOG_NOTICE, "Child (cryptosd) pid: %d", childPid);
                  int returnStatus;
                  waitpid(childPid, &returnStatus, 0);
                  syslog(LOG_NOTICE, "Return Status %d", WEXITSTATUS(returnStatus));
                  if (WIFEXITED(returnStatus)){
                    syslog(LOG_NOTICE, "Encryption done for %s. Beginning with the deletion.", newFilePath);
                    // outfile found, delete the original one

                    pid_t childPid = fork();

                    if (childPid == -1){
                      syslog(LOG_ERR, "Error (%d) during start of rm. Continue without deleting %s", errno, imageDirContent->d_name);
                    }
                    else if(childPid == 0){
                      // Child process
                      syslog(LOG_NOTICE, "Starting deletion of %s", imageDirContent->d_name);
                      char *argList[] = {"rm",
                        newFilePath,
                        NULL
                      };
                      execvp("rm", argList);
                      syslog(LOG_ERR, "Error during execvp of rm for %s", imageDirContent->d_name);
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
                        syslog(LOG_NOTICE, "Deletion done for %s", imageDirContent->d_name);
                      }
                    }
                  }
                  else if ( WIFSIGNALED(returnStatus) ) {
                    int signum = WTERMSIG(returnStatus);
                    syslog(LOG_ERR, "Exited due to receiving signal %d\n", WEXITSTATUS(returnStatus));
                  }
                  else if ( WIFSTOPPED(returnStatus) ) {
                    int signum = WSTOPSIG(returnStatus);
                    syslog(LOG_ERR, "Stopped due to receiving signal %d\n", WEXITSTATUS(returnStatus));
                  }
                  else {
                    // Highly unexpected error
                    syslog(LOG_ERR, "Child (cryptosd) returned with errorcode %d", WEXITSTATUS(returnStatus));
                    // TODO: check if encryption done or not
                  }
                }
              }
            }
            free(newFilePath);
          }
        }
        if (closedir(imageDir) == -1){
          syslog(LOG_ERR, "Error during closing the directory %s", imagePath);
          // TODO: try until you can close it or exit
        }
      }
    }

    int sleepTime = 1;
    syslog(LOG_NOTICE, "Sleep %d seconds", sleepTime);
    sleep(sleepTime);
    syslog(LOG_NOTICE, "before sync");
    sync();
    syslog(LOG_NOTICE, "after sync");
    //sync
    //unmount
    syslog(LOG_NOTICE, "begin umount");
    if (umount("/mnt/sd/") == -1)
    {
      syslog(LOG_ERR, "Unmount failed with errorcode %d", errno);
    }

    syslog(LOG_NOTICE, "end umount");

    if(mount("/dev/mmcblk0p1", "/mnt/sd", "vfat", MS_RELATIME, "errors=continue") == -1)
    {
      syslog(LOG_ERR, "Remount failed with errorcode %d", errno);
    }  
    syslog(LOG_NOTICE, "end remount");
  }

  syslog (LOG_NOTICE, "Cryptodaemon terminated.");
  closelog();

  return EXIT_SUCCESS;
}
