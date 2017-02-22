#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <libssh/libssh.h>
#include <libssh/callbacks.h>

#include <termios.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <pty.h>

int signal_delayed = 0;
struct termios terminal;
ssh_channel chan;
char *cmds[10];

static void sigwindowchanged(int i){
  (void) i;
  signal_delayed=1;
}

static void setsignal(void){
  signal(SIGWINCH, sigwindowchanged);
  signal_delayed=0;
}

static void sizechanged(void){
  struct winsize win = { 0, 0, 0, 0 };
  ioctl(1, TIOCGWINSZ, &win);
  ssh_channel_change_pty_size(chan,win.ws_col, win.ws_row);
  //    printf("Changed pty size\n");
  setsignal();
}

static int auth_callback(const char *prompt, char *buf, size_t len,
			 int echo, int verify, void *userdata) {
  char *answer = NULL;
  char *ptr;

  (void) verify;
  (void) userdata;

  if (echo) {
    while ((answer = fgets(buf, len, stdin)) == NULL);
    if ((ptr = strchr(buf, '\n'))) {
      *ptr = '\0';
    }
  }
  else {
    if (ssh_getpass(prompt, buf, len, 0, 0) < 0) {
      return -1;
    }
    return 0;
  }
  if (answer == NULL) {
    return -1;
  }
  strncpy(buf, answer, len);
  return 0;
}

struct ssh_callbacks_struct cb
= {
  .auth_function=auth_callback,
  .userdata=NULL
};

/*
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
*/
int authenticate_password(ssh_session session)
{
  char *password;
  int rc;
  password = getpass("Enter your password: ");
  rc = ssh_userauth_password(session, NULL, password);
  if (rc == SSH_AUTH_ERROR)
    {
      fprintf(stderr, "Authentication failed: %s\n",
	      ssh_get_error(session));
      return SSH_AUTH_ERROR;
    }
  return rc;
}

static void do_cleanup(int i) {
  /* unused variable */
  (void) i;

  tcsetattr(0,TCSANOW,&terminal);
}

static void select_loop(ssh_session session,ssh_channel channel){
  fd_set fds;
  struct timeval timeout;
  char buffer[4096];
  /* channels will be set to the channels to poll.
   * outchannels will contain the result of the poll
   */
  ssh_channel channels[2], outchannels[2];
  int lus;
  int eof=0;
  int maxfd;
  int ret;
  while(channel){
    do{
      FD_ZERO(&fds);
      if(!eof)
	FD_SET(0,&fds);
      timeout.tv_sec=30;
      timeout.tv_usec=0;
      FD_SET(ssh_get_fd(session),&fds);
      maxfd=ssh_get_fd(session)+1;
      channels[0]=channel; // set the first channel we want to read from
      channels[1]=NULL;
      ret=ssh_select(channels,outchannels,maxfd,&fds,&timeout);
      if(signal_delayed)
	sizechanged();
      if(ret==EINTR)
	continue;
      if(FD_ISSET(0,&fds)){
	lus=read(0,buffer,sizeof(buffer));
	if(lus)
	  ssh_channel_write(channel,buffer,lus);
	else {
	  eof=1;
	  ssh_channel_send_eof(channel);
	}
      }
      if(channel && ssh_channel_is_closed(channel)){
	//ssh_log(session,SSH_LOG_RARE,"exit-status : %d\n",ssh_channel_get_exit_status(channel));

	ssh_channel_free(channel);
	channel=NULL;
	channels[0]=NULL;
      }
      if(outchannels[0]){
	while(channel && ssh_channel_is_open(channel) && ssh_channel_poll(channel,0)!=0){
	  lus=ssh_channel_read(channel,buffer,sizeof(buffer),0);
	  if(lus==-1){
	    fprintf(stderr, "Error reading channel: %s\n",
		    ssh_get_error(session));
	    return;
	  }
	  if(lus==0){
	    //ssh_log(session,SSH_LOG_RARE,"EOF received\n");
	    //ssh_log(session,SSH_LOG_RARE,"exit-status : %d\n",ssh_channel_get_exit_status(channel));

	    ssh_channel_free(channel);
	    channel=channels[0]=NULL;
	  } else
	    if (write(1,buffer,lus) < 0) {
	      fprintf(stderr, "Error writing to buffer\n");
	      return;
	    }
	}
	while(channel && ssh_channel_is_open(channel) && ssh_channel_poll(channel,1)!=0){ /* stderr */
	  lus=ssh_channel_read(channel,buffer,sizeof(buffer),1);
	  if(lus==-1){
	    fprintf(stderr, "Error reading channel: %s\n",
		    ssh_get_error(session));
	    return;
	  }
	  if(lus==0){
	    //ssh_log(session,SSH_LOG_RARE,"EOF received\n");
	    //ssh_log(session,SSH_LOG_RARE,"exit-status : %d\n",ssh_channel_get_exit_status(channel));
	    ssh_channel_free(channel);
	    channel=channels[0]=NULL;
	  } else
	    if (write(2,buffer,lus) < 0) {
	      fprintf(stderr, "Error writing to buffer\n");
	      return;
	    }
	}
      }
      if(channel && ssh_channel_is_closed(channel)){
	ssh_channel_free(channel);
	channel=NULL;
      }
    } while (ret==EINTR || ret==SSH_EINTR);

  }
}

static void shell(ssh_session session){
  ssh_channel channel;
  struct termios terminal_local;
  int interactive=isatty(0);
  channel = ssh_channel_new(session);
  /*
  if(interactive){
    tcgetattr(0,&terminal_local);
    memcpy(&terminal,&terminal_local,sizeof(struct termios));
  }
  */
  if(ssh_channel_open_session(channel)){
    printf("error opening channel : %s\n",ssh_get_error(session));
    return;
  }
  chan=channel;
  /*
  if(interactive){
    ssh_channel_request_pty(channel);
    sizechanged();
  }
  */
  if(ssh_channel_request_shell(channel)){
    printf("Requesting shell : %s\n",ssh_get_error(session));
    return;
  }
  /*
  if(interactive){
    cfmakeraw(&terminal_local);
    tcsetattr(0,TCSANOW,&terminal_local);
    setsignal();
  }
  */
  //signal(SIGTERM,do_cleanup);
  select_loop(session,channel);
  /*
  if(interactive)
    do_cleanup(0);
  */
}

static void batch_shell(ssh_session session){
  ssh_channel channel;
  char buffer[1024];
  int i,s=0;
  for(i=0;i<10 && cmds[i];++i)
    s+=snprintf(buffer+s,sizeof(buffer)-s,"%s ",cmds[i]);
  channel=ssh_channel_new(session);
  ssh_channel_open_session(channel);
  if(ssh_channel_request_exec(channel,buffer)){
    printf("error executing %s : %s\n", buffer,ssh_get_error(session));
    return;
  }
  select_loop(session,channel);
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
  const ssh_key key_filepath = "/home/nilou/.ssh/id_rsa";

  session = ssh_new();
  if (session == NULL)
    return NULL;

  ssh_callbacks_init(&cb);
  ssh_set_callbacks(session,&cb);

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

  /*
    if(verify_knownhost(session, 1) != 0)
    {
    ssh_disconnect(session);
    ssh_free(session);
    
    fprintf(stderr, "Host check failed.\n");
    return NULL;
    }
    
    // We set username as NULL, here, because it was set above. We also set 
    // NULL for the passphrase.
    result = ssh_userauth_publickey(session, NULL, key_filepath);
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
  */

  int rc = authenticate_password(session);
  if (rc == SSH_AUTH_SUCCESS)
    printf("Login successful.\n");
  else
    dprintf(stderr, "Authentication failed: %s\n", ssh_get_error(session));

  //ssh_log(session, SSH_LOG_FUNCTIONS, "Authentication success");
  
  //if(!cmds[0])
    shell(session);
    /*
      else
      
      batch_shell(session);
    */


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
