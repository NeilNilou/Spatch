/*
** cmd3.c for boite in /home/leguen_q/norme_server/servers/src
** 
** Made by Quentin Leguen
** Login   <leguen_q@epitech.net>
** 
** Started on  Thu Jul 24 20:58:06 2014 Quentin Leguen
** Last update Thu Jul 24 21:51:22 2014 Quentin Leguen
*/

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "cmd.h"

int             do_touch(int sok, __attribute__((unused))char *name_client,
			 char *path)
{
  int           rc;
  pid_t         pid;
  char          arg[1024];

  send(sok, "enter arg : ", strlen("enter arg : "), MSG_NOSIGNAL);
  if ((rc = read(sok, arg, 1023)) == -1)
    return (EXIT_FAILURE);
  if (check_path(arg, path, sok) == EXIT_FAILURE)
    return (EXIT_FAILURE);
  if ((pid = fork()) == 0)
    {
      dup2(sok, 1);
      arg[rc -1] = '\0';
      if (execlp("touch", "touch", arg, NULL) == -1)
        return (EXIT_FAILURE);
    }
  else if (pid == -1)
    return (EXIT_FAILURE);
  else
    wait(NULL);
  return (EXIT_SUCCESS);
}
