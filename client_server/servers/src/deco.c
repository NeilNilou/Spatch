/*
** deco.c for boite in /home/leguen_q/norme_server/servers/src
** 
** Made by Quentin Leguen
** Login   <leguen_q@epitech.net>
** 
** Started on  Thu Jul 24 21:12:16 2014 Quentin Leguen
** Last update Thu Jul 24 21:57:13 2014 Quentin Leguen
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

void            del_client_tab(t_infos_client *cl, int cpt,
			       t_infos_server *server)
{
  int		count;

  count = server->nb_clients -1 -cpt;
  memmove(cl + cpt, cl + cpt + 1, (sizeof(cl) * (count)));
  server->nb_clients -= 1;
}

void            dc_client(int fd)
{
  if (close(fd) == -1)
    perror("close");
}
