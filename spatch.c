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

int ssh_handle_key_exchange(ssh_session session);


int main(int argc, char **argv)
{
  unsigned int port = 50555;
	const char *hostname = "127.0.0.1";
	const char *RSA_key = "/etc/ssh/ssh_host_rsa_key";
	const char *DSA_key = "/etc/ssh/ssh_host_dsa_key";
	int log = SSH_LOG_PROTOCOL;
	ssh_bind sshbind;
	ssh_session session;
	int sok;
	struct sockaddr_in sin;
	struct sockaddr_in bind_stock;
	unsigned long hostaddr;
	struct protoent *protocol;
	int ret;
	
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

	ssh_init();
	
	sshbind = ssh_bind_new();
	
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR,  &port);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, hostname);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &log);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, &log);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, RSA_key);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, DSA_key);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, RSA_key);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, DSA_key);
	
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
	    if (ssh_bind_accept(sshbind, session) == SSH_ERROR)
	     fprintf(stderr,"Error accept %s\n", ssh_get_error(sshbind));
	else
	      dprintf(1,"connection Accepted", strlen("connection Accepted"));
	    ssh_handle_key_exchange(session); 
	    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);
	  }
	ssh_bind_free(sshbind);
	ssh_free(session);
}
