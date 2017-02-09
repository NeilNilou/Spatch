/*
** server2.c for caisse in /home/leguen_q/norme_server/servers/src
** 
** Made by Quentin Leguen
** Login   <leguen_q@epitech.net>
** 
** Started on  Thu Jul 24 20:19:53 2014 Quentin Leguen
** Last update Thu Jul 24 20:22:04 2014 Quentin Leguen
*/

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
#include <errno.h>
#include "server.h"
#include "cmd.h"

int                     ret_max(int nb, t_infos_client *cl)
{
  int                   nb_max;

  if (nb == 0)
    return (cl[nb].socket);
  else
    for (int i = 0; i < nb && (i + 1 != nb || i + 1 == nb);
	 i += 1)
      {
        if (cl[i].socket < cl[i + 1].socket)
          nb_max = cl[i + 1].socket;
      }
  return (nb_max);
}
