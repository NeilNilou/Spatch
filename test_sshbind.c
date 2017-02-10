#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>

int main(int argc, char **argv)
{
	int port = 22;
	const char *hostname = "192.168.0.14";
	ssh_bind sshbind;
	ssh_session session;
	ssh_init();
	session = ssh_new();
	sshbind = ssh_bind_new();
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR,  &port);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, hostname);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "ssh-rsa");
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "etc/ssh/ssh_host_rsa_key");
        if (ssh_bind_listen(sshbind) < 0)
	  fprintf(stderr,"error bind %s\n", ssh_get_error(sshbind));
	while (1)
	  {
	    //dprintf(1,"WAITING\n", strlen("WAITING\n"));
	    if (ssh_bind_accept(sshbind, session) ==SSH_ERROR)
	      fprintf(stderr,"error accept %s\n", ssh_get_error(sshbind));
	    else
	      	      dprintf(1,"accepted", strlen("accepted"));
	  }
}
