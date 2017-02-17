#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
//#include <libssh/legacy.h>
#include <libssh/sftp.h>
#include <libssh/ssh2.h>

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

static int auth_password(const char *user, const char *password) {
  if (strcmp(user, "libssh"))
    return 0;
  if (strcmp(password, "libssh"))
    return 0;
  return 1;
}

static int authenticate(ssh_session session) {
  ssh_message message;

  do {
    message= ssh_message_get(session);
    if (!message)
      break;
    switch(ssh_message_type(message)) {
	case SSH_REQUEST_AUTH:
		switch(ssh_message_subtype(message)) {
			case SSH_AUTH_METHOD_PASSWORD:
			  printf("User %s wants to authenticate with a password.\n",
				 ssh_message_auth_user(message), ssh_message_auth_password(message));
			  if (auth_password(ssh_message_auth_user(message), ssh_message_auth_password(message))) {
			    ssh_message_auth_reply_success(message, 0);
			    ssh_message_free(message);
			    return 1;
			  }
			  ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_INTERACTIVE);
			  ssh_message_reply_default(message);
			  break;
			case SSH_AUTH_METHOD_NONE:
			default:
			  printf("User %s wants to authenticate with unknown authentication %d\n",
				 ssh_message_auth_user(message),
				 ssh_message_subtype(message));
			  ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_INTERACTIVE);
			  ssh_message_reply_default(message);
			  break;
		}
		break;
	default:
	  ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_INTERACTIVE);
	  ssh_message_reply_default(message);
    }
    ssh_message_free(message);
  }
  while (1);
  return (0);
}

int main(int argc, char **argv)
{
	unsigned int port = 50555;
	const char *hostname = "127.0.0.1";
	const char *RSA_key = "/etc/ssh/ssh_host_rsa_key";
	const char *DSA_key = "/etc/ssh/ssh_host_dsa_key";
	int log = SSH_LOG_FUNCTIONS;
	ssh_bind sshbind;
	ssh_session session;
	int sok;
	struct sockaddr_in sin;
	struct sockaddr_in bind_stock;
	unsigned long hostaddr;
	struct protoent *protocol;
	int ret;
	int auth=0;

	protocol = getprotobyname("TCP");

	if ((sok = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
	  dprintf(2, "error open socket\n"); 
	else
	  dprintf(1, "socket opened\n");
	

	
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = inet_addr("127.0.0.1"); 
     
	if (bind(sok, (const struct sockaddr *) &sin, sizeof(sin)) ==-1)
	 perror("bind");
	
	if (listen(sok, SOMAXCONN) == -1)
	 perror("listen");

	accept(sok, (struct sockaddr *)&sin, (socklen_t *)&sin);

	ssh_init();
	
	sshbind = ssh_bind_new();
	
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR,  &port);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, hostname);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &log);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, &log);
	//ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, RSA_key);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, DSA_key);
	//ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, RSA_key);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, DSA_key);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BANNER, "Welcome to Spatch !\n");
	
	if (ssh_bind_listen(sshbind) < 0)
	  fprintf(stderr,"error bind %s\n", ssh_get_error(sshbind));
	ssh_bind_set_blocking(sshbind, 0);

	
	//fprintf(stderr, "ssh_handle_key_exchange: %s\n", ssh_get_error(session));

	while (1) {
	    session = ssh_new();
	    
	    if (session == NULL)
	      {
		dprintf(1,"error allocating", strlen("error allocating"));
		continue;
	      }
	    socket_t sessionSocket = ssh_bind_get_fd(sshbind);
	    if (ssh_bind_accept_fd(sshbind, session, sessionSocket) == SSH_ERROR)
	      fprintf(stderr,"Error accepting a connection %s\n", ssh_get_error(sshbind));
	    else {
	      dprintf(1,"Connection accepted.\n", strlen("Connection accepted.\n"));
	    }
	    if (ssh_handle_key_exchange(session) != SSH_OK) {
	      printf("Error : ssh_handle_key_exchange, %s\n", ssh_get_error(sshbind));
	      return 1;
	    }
	    else {
	      ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);
	      printf("ssh_handle_key_exchange: Successful");
	      auth = authenticate(session);
	      if (!auth) {
		printf("Authentication error: %s\n", ssh_get_error(session));
		return 1;
	      }
	    }
	}
	ssh_bind_free(sshbind);
	ssh_free(session);
	return 0;
}
