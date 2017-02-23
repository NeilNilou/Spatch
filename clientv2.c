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

int		signal_delayed = 0;
struct termios	terminal;
ssh_channel	chan;
char *		cmds[10];

static void	sigwindowchanged(int i)
{
  (void) i;
  signal_delayed = 1;
}

static void	setsignal(void) {
  signal(SIGWINCH, sigwindowchanged);
  signal_delayed=0;
}

static void	sizechanged(void) {
  struct winsize win = { 0, 0, 0, 0 };
  ioctl(1, TIOCGWINSZ, &win);
  ssh_channel_change_pty_size(chan,win.ws_col, win.ws_row);
  setsignal();
}

static int	auth_callback(const char *prompt, char *buf, size_t len,
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

struct ssh_callbacks_struct cb
= {
  .auth_function=auth_callback,
    .userdata=NULL
};

int		authenticate_password(ssh_session session)
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

static void	do_cleanup(int i)
{
  (void) i;
  tcsetattr(0,TCSANOW,&terminal);
}

static void	select_loop(ssh_session session,ssh_channel channel)
{
  fd_set fds;
  struct timeval timeout;
  char buffer[4096];
  ssh_channel channels[2], outchannels[2];
  int lus;
  int eof = 0;
  int maxfd;
  int ret;
  
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
	    sizechanged();
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
}

static void	shell(ssh_session session)
{
  ssh_channel channel;
  struct termios terminal_local;
  int interactive = isatty(0);

  channel = ssh_channel_new(session);
  
  if (interactive)
    {
      tcgetattr(0,&terminal_local);
      memcpy(&terminal, &terminal_local, sizeof(struct termios));
    }
  
  if (ssh_channel_open_session(channel))
    {
      printf("Error opening channel : %s\n", ssh_get_error(session));
      return;
    }
  chan = channel;
  
  if (interactive)
    {
      ssh_channel_request_pty(channel);
      sizechanged();
    }

  if (ssh_channel_request_shell(channel))
    {
      printf("Requesting shell : %s\n", ssh_get_error(session));
      return;
    }
  
  if (interactive)
    {
      cfmakeraw(&terminal_local);
      tcsetattr(0, TCSANOW, &terminal_local);
      setsignal();
    }
  
  signal(SIGTERM, do_cleanup);
  select_loop(session, channel);

  if (interactive)
    do_cleanup(0);
}

static void	batch_shell(ssh_session session)
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

ssh_session	connect_ssh()
{
  ssh_session session;
  int auth = 0;
  int result;
  unsigned int port = 50555;

  const char *host = "192.168.1.58";
  const char *user = "nilou";
  const ssh_key key_filepath = "/home/nilou/.ssh/id_rsa";

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

  if (ssh_connect(session))
    {
      fprintf(stderr, "Connection failed : %s\n", ssh_get_error(session));
      ssh_disconnect(session);
      ssh_free(session);
      return NULL;
    }

  printf("Ready to authenticate.\n");
  
  int rc = authenticate_password(session);
  if (rc == SSH_AUTH_SUCCESS)
    printf("Login successful.\n");
  else
    dprintf(stderr, "Authentication failed: %s\n", ssh_get_error(session));
  
  shell(session);
  
  ssh_disconnect(session);
  ssh_free(session);
  return NULL;
}

int main()
{
  ssh_session session = connect_ssh();
  return 0;
}
