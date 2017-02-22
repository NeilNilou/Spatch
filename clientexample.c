#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <libssh/libssh.h>

int verify_knownhost(ssh_session session, int allow_new)
{
    int state, hlen;
    unsigned char *hash = NULL;
    char *hexa;
    char buf[10];
    state = ssh_is_server_known(session);
    hlen = ssh_get_pubkey_hash(session, &hash);

    if (hlen < 0)
        return -1;

    switch (state)
    {
        case SSH_SERVER_KNOWN_OK:
            fprintf(stderr, "The server has been authenticated against an existing host-key.\n");
            break; // ok

        case SSH_SERVER_KNOWN_CHANGED:
            fprintf(stderr, "Host key for server changed: it is now:\n");
            ssh_print_hexa("Public key hash", hash, hlen);
            fprintf(stderr, "For security reasons, connection will be stopped\n");
            free(hash);
            return -1;

        case SSH_SERVER_FOUND_OTHER:
            fprintf(stderr, "The host key for this server was not found but an other"
                "type of key exists.\n");
            fprintf(stderr, "An attacker might change the default server key to"
                "confuse your client into thinking the key does not exist\n");
            free(hash);
            return -1;

        case SSH_SERVER_FILE_NOT_FOUND:
            fprintf(stderr, "Could not find known host file.\n");
            fprintf(stderr, "If you accept the host key here, the file will be"
             "automatically created.\n");
            // fallback to SSH_SERVER_NOT_KNOWN behavior

        case SSH_SERVER_NOT_KNOWN:
            hexa = ssh_get_hexa(hash, hlen);
            fprintf(stderr,"The server is unknown.\n");
            fprintf(stderr, "Public key hash: %s\n", hexa);
            free(hexa);

            if(allow_new == 0)
            {
                fprintf(stderr, "An existing host-key was not found. Our policy is to deny new hosts.\n");            
                return -1;
            }

            fprintf(stderr, "An existing host-key was not found. Adding new host.\n");            
            
            if (ssh_write_knownhost(session) < 0)
            {
                fprintf(stderr, "Error %s\n", strerror(errno));
                free(hash);
                return -1;
            }

            break;

        case SSH_SERVER_ERROR:
            fprintf(stderr, "Error %s", ssh_get_error(session));
            free(hash);
            return -1;
    }
    
    free(hash);
    return 0;
}

ssh_session connect_ssh()
{
    ssh_session session;
    int auth = 0;
    const int verbosity = 1;
    int result;
    unsigned int port = 22;

    const char *host = "127.0.0.1";
    const char *user = "nilou";
    //const char *key_filepath = "/home/nilou/.ssh/id_ecdsa";
//    const char *key_filepath = "/home/dustin/.ssh/id_dsa";
    const char *key_filepath = "/home/nilou/.ssh/id_rsa";

    session = ssh_new();
    if (session == NULL)
        return NULL;

    if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) 
    {
        ssh_free(session);
        return NULL;
    }

    if (ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0) 
    {
        ssh_free(session);
        return NULL;
    }

    if (ssh_options_set(session, SSH_OPTIONS_PORT, &port) < 0)
      {
	ssh_free(session);
	return NULL;
      }

    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    if(ssh_connect(session))
    {
        fprintf(stderr, "Connection failed : %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return NULL;
    }

    printf("Ready to authenticate.\n");

    if(verify_knownhost(session, 1) != 0)
    {
        ssh_disconnect(session);
        ssh_free(session);

        fprintf(stderr, "Host check failed.\n");
        return NULL;
    }

    // We set username as NULL, here, because it was set above. We also set 
    // NULL for the passphrase.
    result = ssh_userauth_privatekey_file(session, NULL, key_filepath, NULL);
    printf("Return from auth.\n");

    if(result != SSH_AUTH_SUCCESS)
    {
        ssh_disconnect(session);
        ssh_free(session);

        switch(result)
        {
            case SSH_AUTH_ERROR:
                fprintf(stderr, "Login failed: auth error\n");
                break;

            case SSH_AUTH_DENIED:
                fprintf(stderr, "Login failed: auth denied\n");
                break;

            case SSH_AUTH_PARTIAL:
                fprintf(stderr, "Login failed: auth partial\n");
                break;

            case SSH_AUTH_AGAIN:
                fprintf(stderr, "Login failed: auth again\n");
                break;
        }

        return NULL;
    }

    printf("Login successful.\n");

/*
  // Authenticate ourselves
  password = getpass("Password: ");
  rc = ssh_userauth_password(my_ssh_session, NULL, password);
  if (rc != SSH_AUTH_SUCCESS)
  {
    fprintf(stderr, "Error authenticating with password: %s\n",
            ssh_get_error(my_ssh_session));
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    exit(-1);
  }
*/

/*
    auth=authenticate_console(session);
    if(auth==SSH_AUTH_SUCCESS){
        return session;
    } else if(auth==SSH_AUTH_DENIED){
        fprintf(stderr,"Authentication failed\n");
    } else {
        fprintf(stderr,"Error while authenticating : %s\n",ssh_get_error(session));
    }
*/
    ssh_disconnect(session);
    ssh_free(session);
    return NULL;
}

int main()
{
        ssh_session session = connect_ssh();

        return 0;
}
