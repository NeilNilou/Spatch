/*
** send2.c for boite in /home/leguen_q/norme_server/servers/src
** 
** Made by Quentin Leguen
** Login   <leguen_q@epitech.net>
** 
** Started on  Thu Jul 24 22:03:17 2014 Quentin Leguen
** Last update Thu Jul 24 22:04:44 2014 Quentin Leguen
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

char            *create_pwd()
{
  int           rdm;
  char          *str;

  srand(time(NULL));
  if ((str = malloc(sizeof(char ) * 8)) == NULL)
    perror("malloc");
  str[7] = '\0';
  for (int i = 0; i != 8; i += 1)
    {
      rdm = rand() % (126 - 33) + 33;
      str[i] = rdm;
    }
  return (str);
}

int             login(int sok, t_infos_client *cl, int i)
{
  int           ret;
  int           rc;
  char          buffer[1024];

  if ((ret = send(sok, "plz enter your login max 6 : ",
                  strlen("plz enter your login max 6 : "),
                  MSG_NOSIGNAL)) == -1)
    perror("send");
  if ((rc = read(sok, buffer, 7)) == -1)
    perror("read");
  buffer[rc - 1] = '\0';
  if ((cl[i].name = strndup(buffer, rc -1)) == NULL)
    return (EXIT_FAILURE);
  cl[i].name[rc -1] = '\0';
  if ((create_file_user(i, rc, sok, cl)) == EXIT_FAILURE)
    return (EXIT_FAILURE);
  return (EXIT_SUCCESS);
}

int             create_dir(char *str, int size)
{
  pid_t         pid;
  char          _getcwd[500];

  memset(_getcwd, 0, 499);
  getcwd(_getcwd, 499);
  strncat(_getcwd, str, size);
  pid = fork();
  if (pid == -1)
    {
      perror("fork");
      return (EXIT_FAILURE);
    }
  if (pid == 0)
    {
      if ((execlp("mkdir", "mkdir", _getcwd, NULL)) == -1)
        {
          perror("(execlp");
          return (EXIT_SUCCESS);
        }
    }
  else
    wait(NULL);
  return (EXIT_SUCCESS);
}
