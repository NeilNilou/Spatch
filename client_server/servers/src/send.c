/*
** send.c for irc in /home/leguen_q/tcp/tp_ex
** 
** Made by Quentin Leguen
** Login   <leguen_q@epitech.net>
** 
** Started on  Sun Apr 27 22:16:05 2014 Quentin Leguen
** Last update Thu Jul 24 23:08:03 2014 Quentin Leguen
*/

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "server.h"
#include "cmd.h"

char		*path_reel;

int		create_file_user(int i, int size,
				 __attribute__((unused))int sok, t_infos_client *cl)
{
  char		_getcwd[1024];
  static	int c = 0;
  int		fd;
  
  if (c == 0)
    {
      getcwd(_getcwd, 1023);
      path_reel = strndup(_getcwd, (int)strlen(_getcwd));
      c++;
    }
  else
    chdir(path_reel);
  size -= 1;
  create_dir(strdup("/save_passwd"), 12);
  create_dir(strdup("/save_con"), 9);
  memset(_getcwd, 0, 1023);
  getcwd(_getcwd, 1023);
  strncat(_getcwd, "/save_passwd/", 13);
  strncat(_getcwd, cl[i].name, strlen(cl[i].name));
  fd = open(_getcwd, O_RDWR, S_IRWXU);
  if (fd == -1)
    create_user(_getcwd, cl[i].socket, cl, i);
  else
    if (already_exist(cl[i].socket, _getcwd ,cl, i, fd) == EXIT_FAILURE)
      return (EXIT_FAILURE);
  return (EXIT_SUCCESS);
}

int		create_user(char *_getcwd, int sok, t_infos_client *cl, int i)
{
  int		fd;
  pid_t		pid;
  char		*pwd;

  fd = open(_getcwd, O_WRONLY | O_TRUNC | O_CREAT, S_IRWXU);
  pwd = create_pwd();
  dprintf(1, "getcwd = %s\n", _getcwd);
  dprintf(1, "pwd = %s\n", pwd);
  write(fd, pwd, 8);
  send(sok, "your passwd is : ", 17, MSG_NOSIGNAL);
  send(sok, pwd, 8, MSG_NOSIGNAL);
  send(sok, "\n", 1, MSG_NOSIGNAL);
  getcwd(_getcwd, 1023);
  strncat(_getcwd, "/save_con/", 10);
  strncat(_getcwd, cl[i].name, strlen(cl[i].name));
  cl[i].directory = strdup(_getcwd);
  if ((pid = fork()) == 0)
    {
      if (execlp("mkdir", "mkdir", _getcwd, NULL) == -1)
	return (EXIT_FAILURE);
    }
  else
    wait(NULL);
  cl[i].first_co = 0;
  return (EXIT_SUCCESS);
}

int		already_exist(int sok, char *_getcwd, t_infos_client *cl, 
			      int i, int fd)
{
  char		passwd_file[500];
  char		passwd_client[500];
  int		rc;
  
  send(sok, "plz enter your passwd : ", 24, MSG_NOSIGNAL);
  memset(passwd_client, 0, 499);
  read(sok, passwd_client, 499);
  if ((rc = read(fd, passwd_file, 8)) == -1)
    perror("read");
  if (strncmp(passwd_client, passwd_file, 8) == 0)
    {
      dprintf(sok, "passwd is correct you have access to the server\n");
      getcwd(_getcwd, 1023);
      strncat(_getcwd, "/save_con/" , 10);
      strncat(_getcwd, cl[i].name, strlen(cl[i].name));
      cl[i].directory = strdup(_getcwd);
      cl[i].first_co = 0;
    }
  else
    {
      write(sok, "passwd is not correct plz reconnect\n",
	    strlen("passwd is not correct plz reconnect\n"));
      return (EXIT_FAILURE);
    }
  return (EXIT_SUCCESS);
}
