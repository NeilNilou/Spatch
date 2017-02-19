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

#ifdef _WIN32

#define KEYS_FOLDER

#else

#define KEYS_FOLDER "./ssh_keys/"

#endif

static socket_t bind_socket(ssh_bind sshbind, const char *hostname, int port) {
  struct hostent *hp = NULL;
  socket_t s;
  int opt = 1;
  struct sockaddr_in bindstock;
  int fd;
  
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
  return s;
}

int main() {
  ssh_bind sshbind;
  const char *host = "127.0.0.1";
  int port = 50555;
  ssh_session session;
  int fd;
  int log = SSH_LOG_FUNCTIONS;
  
  fd = bind_socket(sshbind, host, port);
  if (listen(fd, 10) < 0) {
    fprintf(stderr,"Error listening, %s\n", ssh_get_error(sshbind));
    close(fd);
    return -1;
  }

  ssh_init();
  sshbind = ssh_bind_new();
  session = ssh_new();

  ssh_bind_set_fd(sshbind, fd);
  
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR,  &port);
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, host);
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &log);
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, &log);
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "ssh-rsa");
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "ssh-dsa");
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "ssh_host_dsa_key");
  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BANNER, "Welcome to Spatch !\n");

  if (ssh_bind_listen(sshbind) < 0)
    fprintf(stderr,"error bind %s\n", ssh_get_error(sshbind));
  ssh_bind_set_blocking(sshbind, 0);

  while (1) {
    if (ssh_bind_accept_fd(sshbind, session, fd) != SSH_ERROR) {
      dprintf(stdout, "Connection accepted.\n", strlen("Connection accepted.\n"));
    }
    else {
      dprintf(stderr, "Error accepting a connection.\n", strlen("Error accepting a connection.\n"));
      return -1;
    }
    if (ssh_handle_key_exchange(session) != SSH_OK) {
      printf("Error : ssh_handle_key_exchange, %s\n", ssh_get_error(sshbind));
      return 1;
    }
  }
  return 0;
}
