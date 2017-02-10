#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>


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

int main(int argc, char **argv)
{
	unsigned int port = 22;
	const char *hostname = "192.168.1.58";
	const char *RSA_key = "/etc/ssh/ssh_host_rsa_key";
	int log = SSH_LOG_PROTOCOL;
	ssh_bind sshbind;
	ssh_session session;
	int sok;
	struct sockaddr_in sin;
	unsigned long hostaddr;
	struct protoent *protocol;
	
	protocol = getprotobyname("TCP");

	if ((sok = socket(AF_INET, SOCK_STREAM, protocol->p_proto)) == -1) {
	  dprintf(2, "error open socket\n");
	}
	else {
	  dprintf(1, "Socket opened\n");
	}

	sin.sin_family = AF_INET;
	sin.sin_port = htons(22);
	sin.sin_addr.s_addr = INADDR_ANY;
	
	ssh_init();
	session = ssh_new();
	sshbind = ssh_bind_new();
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR,  &port);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, hostname);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &log);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, &log);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, RSA_key);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, RSA_key);
	if (ssh_bind_listen(sshbind) < 0)
	  fprintf(stderr,"error bind %s\n", ssh_get_error(sshbind));
	ssh_bind_set_blocking(sshbind, 0);
	while (1) {
	  //dprintf(1,"WAITING\n", strlen("WAITING\n"));
	  if (ssh_bind_accept(sshbind, session) == SSH_ERROR)
	    fprintf(stderr,"Error accept %s\n", ssh_get_error(sshbind));
	  else
	    dprintf(1,"Accepted", strlen("Accepted"));
	}
	ssh_bind_free(sshbind);
	ssh_free(session);
}
