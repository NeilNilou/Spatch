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
#include <poll.h>
#include <pty.h>
#include <libssh/callbacks.h>
#include <termios.h>
#include <sys/select.h>
#include <sys/time.h>

#ifdef _WIN32

#define KEYS_FOLDER

#else

#define KEYS_FOLDER "/etc/ssh/"

#endif

int use_syslog = 0;
int verbose = 0;

// VARIABLES POUR LE CLIENT
int signal_delayed = 0;
struct termios terminal;
//ssh_channel chan;
ssh_channel chan_sized;
char *cmds[10];
// ------------------------

void logger(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vprintf(fmt, ap);
  printf("\n");
  if (use_syslog)
    vsyslog(LOG_NOTICE, fmt, ap);
  va_end(ap);
}

/*
static int auth_password(const char *user, const char *password) {
  if(strcmp(user,"nilou"))
    return 0;
  if(strcmp(password,"TestSpatch"))
    return 0;
  return 1; // authenticated  
}
*/

void handle_sigchild(int signum) {
  int status = -1;
  int pid = 0;
  do {
    int pid = waitpid(-1, &status, WNOHANG);
    if (verbose > 0)
      logger("Process %d Exited", pid);
  } while(pid > 0);
}

static int copy_fd_to_chan(socket_t fd, int revents, void *userdata) {
  ssh_channel chan = (ssh_channel)userdata;
  char buf[2048];
  int sz = 0;

  if(!chan) {
    close(fd);
    return -1;
  }
  if(revents & POLLIN) {
    sz = read(fd, buf, 2048);
    if(sz > 0) {
      ssh_channel_write(chan, buf, sz);
    }
  }
  if(revents & POLLHUP) {
    ssh_channel_close(chan);
    sz = -1;
  }
  return sz;
}

static int copy_chan_to_fd(ssh_session session,
			   ssh_channel channel,
			   void *data,
			   uint32_t len,
			   int is_stderr,
			   void *userdata) {
  int fd = *(int*)userdata;
  int sz;
  (void)session;
  (void)channel;
  (void)is_stderr;
  sz = write(fd, data, len);
  return sz;
}

static void chan_close(ssh_session session, ssh_channel channel, void *userdata) {
  int fd = *(int*)userdata;
  (void)session;
  (void)channel;
  close(fd);
}

struct ssh_channel_callbacks_struct cb = {
  .channel_data_function = copy_chan_to_fd,
  .channel_eof_function = chan_close,
  .channel_close_function = chan_close,
  .userdata = NULL
};

static int main_loop(ssh_channel chan) {
  ssh_session session = ssh_channel_get_session(chan);
  socket_t fd;
  struct termios *term = NULL;
  struct winsize *win = NULL;
  pid_t childpid;
  ssh_event event;
  short events;

  childpid = forkpty(&fd, NULL, term, win);
  if(childpid == 0) {
    execl("/bin/bash", "/bin/bash", (char *)NULL);
    abort();
  }
  cb.userdata = &fd;
  ssh_callbacks_init(&cb);
  ssh_set_channel_callbacks(chan, &cb);
  events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;
  event = ssh_event_new();
  if(event == NULL) {
    printf("Couldn't get a event\n");
    return -1;
  }
  if(ssh_event_add_fd(event, fd, events, copy_fd_to_chan, chan) != SSH_OK) {
    printf("Couldn't add an fd to the event\n");
    return -1;
  }
  if(ssh_event_add_session(event, session) != SSH_OK) {
    printf("Couldn't add the session to the event\n");
    return -1;
  }
  do {
    ssh_event_dopoll(event, 1000);
  }
  while(!ssh_channel_is_closed(chan));
  ssh_event_remove_fd(event, fd);
  ssh_event_remove_session(event, session);
  ssh_event_free(event);
  return 0;
}

void	error_usage()
{
  fprintf(stderr, "Usage: sudo ./spatch [port_listened] [ip_dest] [port_dest]\n");
}

/*
**
** CODE CLIENT
**
*/

static void sigwindowchanged(int i)
{
  (void) i;
  signal_delayed = 1;
}

static void setsignal(void) {
  signal(SIGWINCH, sigwindowchanged);
  signal_delayed=0;
}

static void sizechanged() {
  struct winsize win = { 0, 0, 0, 0 };
  ioctl(1, TIOCGWINSZ, &win);
  printf("avant change pty size\n");
  ssh_channel_change_pty_size(chan_sized, win.ws_col, win.ws_row);
  printf("après change pty size\n");
  setsignal();
}

static int auth_callback(const char *prompt, char *buf, size_t len,
			int echo, int verify, void *userdata) {
  char *answer = NULL;
  char *ptr;

  (void) verify;
  (void) userdata;

  if (echo)
    {
      while ((answer = fgets(buf, len, stdin)) == NULL);
      if ((ptr = strchr(buf, '\n')))
	*ptr = '\0';
    }
  else
    {
      if (ssh_getpass(prompt, buf, len, 0, 0) < 0)
	return -1;
      return 0;
    }
  if (answer == NULL)
    return -1;
  strncpy(buf, answer, len);
  return 0;
}

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

static void do_cleanup(int i)
{
  (void) i;
  tcsetattr(0,TCSANOW,&terminal);
}

static void select_loop(ssh_session session, ssh_channel channel)
{
  fd_set fds;
  struct timeval timeout;
  char buffer[4096];
  ssh_channel channels[2], outchannels[2];
  int lus;
  int eof = 0;
  int maxfd;
  int ret;

  printf("DANS SELECT LOOP\n");
  
  while(channel)
    {
            do
	      {
		FD_ZERO(&fds);
		if (!eof)
		  FD_SET(0,&fds);
		timeout.tv_sec = 30;
		timeout.tv_usec = 0;
		FD_SET(ssh_get_fd(session),&fds);
		maxfd=ssh_get_fd(session)+1;
		channels[0] = channel;
		channels[1] = NULL;
		ret = ssh_select(channels,outchannels,maxfd,&fds,&timeout);
		if (signal_delayed)
		  sizechanged(channel);
		if (ret == EINTR)
		  continue;
		if (FD_ISSET(0, &fds))
		  {
		    lus=read(0, buffer, sizeof(buffer));
		    if (lus)
		      ssh_channel_write(channel, buffer, lus);
		    else
		      {
			eof = 1;
			ssh_channel_send_eof(channel);
		      }
		  }
		if (channel && ssh_channel_is_closed(channel))
		  {
		    ssh_log(session, SSH_LOG_RARE, "Exit-status : %d\n", ssh_channel_get_exit_status(channel));
		    ssh_channel_free(channel);
		    channel = NULL;
		    channels[0] = NULL;
		  }
		if (outchannels[0])
		  {
		    while (channel && ssh_channel_is_open(channel) && ssh_channel_poll(channel, 0) != 0)
		      {
			lus = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
			if (lus == -1)
			  {
			    fprintf(stderr, "Error reading channel: %s\n", ssh_get_error(session));
			    return;
			  }
			if (lus == 0)
			  {
			    ssh_log(session,SSH_LOG_RARE, "EOF received\n");
			    ssh_log(session,SSH_LOG_RARE, "exit-status : %d\n", ssh_channel_get_exit_status(channel));
			    ssh_channel_free(channel);
			    channel=channels[0]=NULL;
			  }
			else
			  if (write(1, buffer, lus) < 0)
			    {
			      fprintf(stderr, "Error writing to buffer\n");
			      return;
			    }
		      }
		    while (channel && ssh_channel_is_open(channel) && ssh_channel_poll(channel, 1) != 0)
		      {
			lus = ssh_channel_read(channel, buffer, sizeof(buffer), 1);
			if (lus == -1)
			  {
			    fprintf(stderr, "Error reading channel: %s\n", ssh_get_error(session));
			    return;
			  }
			if (lus == 0)
			  {
			    ssh_log(session,SSH_LOG_RARE, "EOF received\n");
			    ssh_log(session,SSH_LOG_RARE, "Exit-status : %d\n", ssh_channel_get_exit_status(channel));
			    ssh_channel_free(channel);
			    channel = channels[0] = NULL;
			  }
			else
			  if (write(2, buffer, lus) < 0)
			    {
			      fprintf(stderr, "Error writing to buffer\n");
			      return;
			    }
		      }
		  }
		if (channel && ssh_channel_is_closed(channel))
		  {
		    ssh_channel_free(channel);
		    channel = NULL;
		  }
	      }
	    while (ret == EINTR || ret == SSH_EINTR);

    }
  printf("FIN DE SELECT LOOP\n");
}

static void shell(ssh_session session, ssh_channel channel)
{
  struct termios terminal_local;
  int interactive = isatty(0);

  printf("Dans shell\n");

  printf("après channel new\n");
  if (interactive)
    {
      tcgetattr(0,&terminal_local);
      memcpy(&terminal, &terminal_local, sizeof(struct termios));
    }
  printf("après tcgetattr\n");

  /*
  if (ssh_channel_open_session(channel))
    {
      printf("Error opening channel : %s\n", ssh_get_error(session));
      return;
    }
  */
  chan_sized = channel;
  printf("après chan channel\n");
  
  if (interactive)
    {
      ssh_channel_request_pty(channel);
      sizechanged();
    }

  printf("après channel request pty\n");

  /*
  if (ssh_channel_request_shell(channel))
    {
      printf("Requesting shell : %s\n", ssh_get_error(session));
      return;
    }
  */
  
  printf("après channel request shell\n");

  if (interactive)
    {
      cfmakeraw(&terminal_local);
      tcsetattr(0, TCSANOW, &terminal_local);
      setsignal();
    }

  printf("avant select loop\n");
  signal(SIGTERM, do_cleanup);
  printf("après signal\n");
  select_loop(session, channel);

  printf("Après select loop\n");

  if (interactive)
    do_cleanup(0);
}

static void batch_shell(ssh_session session)
{
  ssh_channel channel;
  char buffer[1024];
  int i;
  int s = 0;

  for (i = 0; i < 10 && cmds[i]; ++i)
    s += snprintf(buffer+s, sizeof(buffer)-s, "%s ", cmds[i]);
  channel = ssh_channel_new(session);
  ssh_channel_open_session(channel);
  if (ssh_channel_request_exec(channel, buffer))
    {
      printf("error executing %s : %s\n", buffer,ssh_get_error(session));
      return;
    }
  select_loop(session, channel);
}

ssh_session connect_ssh(ssh_session session, ssh_channel channel, socket_t sock)
{
  int auth = 0;
  int result;
  unsigned int port = 22;

  const char *host = "127.0.0.1";
  //const char *user = "nilou";
  const ssh_key key_filepath = "/home/nilou/.ssh/id_rsa";

  session = ssh_new();
  if (session == NULL)
    return NULL;

  /*
  if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0)
    {
      ssh_free(session);
      return NULL;
    }
  */

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

  if (ssh_connect(session))
    {
      fprintf(stderr, "Connection failed : %s\n", ssh_get_error(session));
      ssh_disconnect(session);
      ssh_free(session);
      return NULL;
    }

  printf("Ready to authenticate.\n");
  /*
  int rc = authenticate_password(session);
  if (rc == SSH_AUTH_SUCCESS)
    printf("Login successful.\n");
  else
    dprintf(stderr, "Authentication failed: %s\n", ssh_get_error(session));
  */
  shell(session, channel);

  ssh_disconnect(session);
  ssh_free(session);
  return NULL;
}

/*
**
** CODE CLIENT
**
*/


int main(int argc, char **argv)
{
  ssh_bind sshbind;
  //const char *host = "127.0.0.1";
  //char *port = "50555";
  ssh_session session;
  ssh_session session2;
  int fd;
  int log = SSH_LOG_FUNCTIONS;  
  int r = -1;
  int sftp = 0;
  char buf[2048];
  int i;
  int shell = 0;

  if (argc != 4) {
    error_usage();
    return (-1);
  }
  
  sshbind = ssh_bind_new();

  ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, argv[1]);
  //ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, host);
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
    {
      dprintf(1,"error allocating", strlen("error allocating"));  
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

    /* AUTHENTICATION */
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
	    //  if (auth_password(ssh_message_auth_user(message), ssh_message_auth_password(message))) {
	    auth=1;
	    socket_t sock;
	    sock = ssh_bind_get_fd(sshbind);
	    //write(sock, "test", strlen("test"));
	    ssh_message_auth_reply_success(message,0);
	    break;
	    //}
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
    while(!auth);
    if(!auth){
      printf("auth error: %s\n", ssh_get_error(session));
      ssh_disconnect(session);
      return 1;
    }
    
    /* GET THE CHANNEL */
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
    //main_loop(chan);
    printf("Client is called\n");
    session2 = connect_ssh(session2, chan, sock);
  }
  
 error:
  ssh_disconnect(session);
  ssh_free(session);
  ssh_bind_free(sshbind);
  logger("Connection Closed From %s", peername);
  return 0;
}
