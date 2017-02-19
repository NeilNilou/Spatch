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

#ifdef _WIN32

#define KEYS_FOLDER

#else

#define KEYS_FOLDER "./ssh_keys/"

#endif

int use_syslog = 0;
int verbose = 0;

void handle_sigchild(int signum) {
  int status = -1;
  int pid = 0;
  do {
    int pid = waitpid(-1, &status, WNOHANG);
    if (verbose > 0)
      logger("Process %d Exited", pid);
  } while(pid > 0);
}

void logger(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vprintf(fmt, ap);
  printf("\n");
  if (use_syslog)
    vsyslog(LOG_NOTICE, fmt, ap);
  va_end(ap);
}

static socket_t bind_socket(ssh_bind sshbind, const char *hostname, int port) {
  struct hostent *hp = NULL;
  socket_t s;
  int opt = 1;
  struct sockaddr_in bindstock;
  
  s = socket(PF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    fprintf(stderr,"Error: %s\n", ssh_get_error(sshbind));
    return -1;
  }
  
  hp = gethostbyname(hostname);
  
  bindstock.sin_family = AF_INET;
  bindstock.sin_port = htons(port);
  bindstock.sin_addr.s_addr = INADDR_ANY;
    
  if (hp == NULL) {
    fprintf(stderr,"Error: %s\n", ssh_get_error(sshbind));
    close(s);
    return -1;
  }
  
  if (bind(s, (struct sockaddr *)&bindstock, sizeof(bindstock)) < 0) {
    fprintf(stderr,"Error: %s\n", ssh_get_error(sshbind));
    close(s);
    return -1;
  }

  if (listen(s, 10) < 0) {
    fprintf(stderr,"Error listening, %s\n", ssh_get_error(sshbind));
    close(s);
    return -1;
  }
  accept(s, (struct sockaddr *)&bindstock, (socklen_t *)&bindstock);
  
  return s;
}

int main() {
  ssh_bind sshbind;
  const char *host = "127.0.0.1";
  char *port = "50555";
  ssh_session session;
  int fd;
  int log = SSH_LOG_FUNCTIONS;
  ssh_key pkey;
  int r = -1;
  
  //fd = bind_socket(sshbind, host, port);
  //ssh_init();
  sshbind = ssh_bind_new();
  
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR,  port);
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, host);
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &log);
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, &log);
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "ssh-rsa");
  //ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "ssh-dsa");
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");
  //ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "ssh_host_dsa_key");
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BANNER, "Welcome to Spatch !\n");

  if (ssh_bind_listen(sshbind) < 0)
    fprintf(stderr,"error bind %s\n", ssh_get_error(sshbind));
  ssh_bind_set_blocking(sshbind, 0);

  signal(SIGCHLD, &handle_sigchild);
  
 restart:
  session = ssh_new();
  
  //while (1) {
  //ssh_bind_set_fd(sshbind, fd);
    if (session == NULL)
      {
	dprintf(1,"error allocating", strlen("error allocating"));
	//continue;
      }
    r = ssh_bind_accept(sshbind, session);
    if (r == SSH_ERROR) {
      logger("Error accepting connection: %s", ssh_get_error(sshbind));
      goto restart;
    }

    int ret = fork();
    if (fork < 0) {
      logger("fork: %s", strerror(errno));
      logger("exiting ...");
      exit(EXIT_FAILURE);
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
    logger("Connection From %s:%d", peername, 50555);

    /*
    if (ssh_pki_import_privkey_file("/etc/ssh/ssh_host_dsa_key", NULL, NULL, NULL, &pkey) == SSH_OK) {
      dprintf(1,"DSA key imported successfully.\n", strlen("DSA key imported successfully.\n"));
    }
    else {
      fprintf(stderr,"Error: Failed to import DSA key, %s\n", ssh_get_error(sshbind));
    }
    */
    if (ssh_handle_key_exchange(session) != SSH_OK) {
      printf("Error: ssh_handle_key_exchange, %s\n", ssh_get_error(sshbind));
      return 1;
    }
    else {
      int auth = 0;
      int authdelay = 0;
      int doubledelay = 0;
      int maxfail = 0;
      do {
	ssh_message message = ssh_message_get(session);
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
	      ssh_message_free(message);
	      //goto error;
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
      while(auth == 0);
    }
  return 0;
}
