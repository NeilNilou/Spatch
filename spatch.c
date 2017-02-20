#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <signal.h>
#include <libssh/callbacks.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <fcntl.h>
#include <utmp.h>

#ifdef _WIN32
#define KEYS_FOLDER
#else
#define KEYS_FOLDER "/etc/ssh/"
#endif

int use_syslog = 0;
int verbose = 0;

static int auth_password(const char user, const char password)
{
  if(strcmp(user, "nilou"))
    return 0;
  if(strcmp(password, "TestSpatch"))
    return 0;
  return 1; // authenticated
}

void logger(const char *fmt, ...) {
  va_list ap;
  int use_syslog;

  va_start(ap, fmt);
  vprintf(fmt, ap);
  printf("\n");
  if (use_syslog)
    vsyslog(LOG_NOTICE, fmt, ap);
  va_end(ap);
}

void handle_sigchild(int signum) {
  int status = -1;
  int pid = 0;
  do {
    int pid = waitpid(-1, &status, WNOHANG);
    if (verbose > 0)
      logger("Process %d Exited", pid);
  } while(pid > 0);
}

int main()
{
  ssh_bind sshbind;
  const char *host = "127.0.0.1";
  char *port = "50555";
  ssh_session session;
  int fd;
  int log = SSH_LOG_FUNCTIONS;
  char buf[2048];
  int i;

  sshbind = ssh_bind_new();
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR,  port);
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, host);
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &log);
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, &log);
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "ssh_host_dsa_key");

  if (ssh_bind_listen(sshbind) < 0)
    fprintf(stderr,"error bind %s\n", ssh_get_error(sshbind));

  signal(SIGCHLD, &handle_sigchild);

 restart:
   session = ssh_new();

   if (session == NULL)
     dprintf(1,"error allocating", strlen("error allocating"));

   r = ssh_bind_accept(sshbind, session);
   if (r == SSH_ERROR) {
     logger("Error accepting connection: %s", ssh_get_error(sshbind));
     goto restart
   }

   int sockfd = ssh_get_fd(session);

   struct sockaddr_in peer;
   socklen_t peer_len = sizeof(peer);
   char *peername = 0;
   int attempts = 0;

   if (ret > 0) {
     if (verbose > 0)
       logger("Started Process %d", ret);
     ssh_free(session);
     goto restart;
   }
   ret = getpeername(sockfd, (struct sockaddr *) &peer, &peer_len);
   peername = inet_ntoa(peer.sin_addr);
   fprintf(sockfd, "Connection From %s:%d", peername, 50555);
   logger("Connection From %s:%d", peername, 50555);

   if (ssh_handle_key_exchange(session) != SSH_OK) {
     printf("Error: ssh_handle_key_exchange, %s\n", ssh_get_error(sshbind));
     goto error;
   }
   else {
     int auth = 0;
     int authdelay = 0;
     int doubledelay = 0;
     int maxfail = 0;
     ssh_message message;
     ssh_channel chan = 0;

     /* A U T H E N T I C A T I O N */
     do {
       message = ssh_message_get(session);
       if (message == NULL)
	 break;

       switch(ssh_message_type(message)) {
       case SSH_REQUEST_AUTH:
	 switch(ssh_message_subtype(message)) {
	 case SSH_AUTH_METHOD_PASSWORD:
	   attempts++;
	   logger("IP: %s USER: %s PASS: %s", peername, ssh_message_auth_user(message), ssh_message_auth_password(message));
	   if (authdelay > 0)
	     sleep(authdelay);
	   if (doubledelay)
	     authdelay *= 2;
	   if (attempts > maxfail) {
	     if (verbose > 1)
	       logger("Max failures reached");
	     if (auth_password(ssh_message_auth_user(message), ssh_message_auth_password(message))) {
	       auth=1;
	       ssh_message_auth_reply_success(message,0);
	       break;
	     }
	     if (ssh_userauth_password(session, "nilou", "TestSpatch") != SSH_AUTH_SUCCESS) {
	       fprintf(stderr, "Unable to authenticate user: nilou\n");
	     }
	     else {
	       fprintf(stdin, "User successfully authenticated\n");
	     }
	     ssh_message_free(message);
	     goto error;
	   }
	 case SSH_AUTH_METHOD_NONE:
	   if (verbose > 1)
	     logger("AUTH_METHOD_NONE Requested");
	   // break missing on purpose
	 default:
	   if (verbose > 1)
	     logger("REQUEST_AUTH: %d", ssh_message_subtype(message));
	   ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
	   ssh_message_reply_default(message);
	   break;
	 }
	 break;
       default:
	 if (verbose > 0)
	   logger("Message Type: %d", ssh_message_type(message));
	 ssh_message_reply_default(message);
	 break;
       }
       ssh_message_free(message);
     }
     while (!auth);
     if(!auth){
       printf("auth error: %s\n",ssh_get_error(session));
       ssh_disconnect(session);
       return 1;
     }

     /* W A I T  F O R  A  C H A N N E L  S E S S I O N */
     do {
       message=ssh_message_get(session);
       if(message){
	 switch(ssh_message_type(message)){
	 case SSH_REQUEST_CHANNEL_OPEN:
	   if(ssh_message_subtype(message)==SSH_CHANNEL_SESSION){
	     chan=ssh_message_channel_request_open_reply_accept(message);
	     break;
	   }
	 default:
	   ssh_message_reply_default(message);
	 }
	 ssh_message_free(message);
       }
     }
     while(message && !chan);
     if(!chan){
       printf("error : %s\n",ssh_get_error(session));
       ssh_finalize();
       return 1;
     }

     /* W A I T  F O R  A  S H E L L */
     do {
       message = ssh_message_get(session);
       if(message != NULL) {
	 if(ssh_message_type(message) == SSH_REQUEST_CHANNEL) {
	   if(ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SHELL) {
	     shell = 1;
	     ssh_message_channel_request_reply_success(message);
	     ssh_message_free(message);
	     break;
	   }
	   else if(ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_PTY) {
	     ssh_message_channel_request_reply_success(message);
	     ssh_message_free(message);
	     continue;
	   }
	 }
	 ssh_message_reply_default(message);
	 ssh_message_free(message);
       }
       else {
	 break;
       }
     }
     while(!shell);

     if(!shell) {
       printf("Error: No shell requested (%s)\n", ssh_get_error(session));
       return 1;
     }

     printf("It works !\n");
   }
}
