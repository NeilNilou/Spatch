/*
** server.c for server in /home/leguen_q/tcp/tp_ex
** 
** Made by Quentin Leguen
** Login   <leguen_q@epitech.net>
** 
** Started on  Fri Apr 25 19:16:45 2014 Quentin Leguen
** Last update Thu Jul 24 21:50:42 2014 Quentin Leguen
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

char			*path_basic;
int			max_sok = 3;

int			init_connection(int port)
{
  int			ret;
  int			sok;
  struct protoent       *protocol;
  struct sockaddr_in	bind_stock;

  protocol = getprotobyname("TCP");
  if ((sok = socket(AF_INET, SOCK_STREAM, protocol->p_proto)) == -1)
    dprintf(2, "error open socket\n");
  bind_stock.sin_family = AF_INET;
  bind_stock.sin_port = htons(port);
  bind_stock.sin_addr.s_addr = INADDR_ANY;
  if ((ret = bind(sok, (const struct sockaddr *) &bind_stock,
		  sizeof(bind_stock))) == -1)
    {
      perror("bind");
      close(sok);
      exit(EXIT_FAILURE);
    }
  if ((ret = listen(sok, SOMAXCONN)) == -1)
    {
      perror("listen");
      close(sok);
      exit(EXIT_FAILURE);
    }
  return (sok);
}

int			connection_new_client(t_infos_client *cl,
					      t_infos_server *server, fd_set *readfs)
{
  struct sockaddr_in    client;

  cl[server->nb_clients].socket =
    accept(server->sock_server, (struct sockaddr *)&client,
	   (socklen_t *)&(server->size_client));
  if (cl[server->nb_clients].socket == -1)
    {
      perror("accept");
      return (EXIT_FAILURE);
    }
  dprintf(1, "A new client is connected on socket %d\n",
	  cl[server->nb_clients].socket);
  max_sok = ret_max(server->nb_clients, cl);
  FD_SET(cl[server->nb_clients].socket, readfs);
  if ((login(cl[server->nb_clients].socket, cl, server->nb_clients))
      == EXIT_FAILURE)
    login(cl[server->nb_clients].socket, cl, server->nb_clients);
  server->nb_clients = server->nb_clients + 1;
  if (server->nb_clients == 500)
    {
      dprintf(2, "nbr max of clients raised\n");
      exit(0);
    }
  return (EXIT_SUCCESS);
}

void			begin_loop(t_infos_server *server,
				   fd_set *readfs, t_infos_client *cl)
{
  int			rc;
  char			buffer[1024];

  for (int i = 0; i < server->nb_clients; i += 1)
    {
      if (FD_ISSET(cl[i].socket, readfs))
  	{
  	  rc = read(cl[i].socket, buffer, 1023);
  	  if (rc == 0)
  	    {
  	      dc_client(cl[i].socket);
	      del_client_tab(cl, i, server);
	      i = 0;
	    }
	  else
	    {
	      write(1, buffer, rc);
	      match_cmd(buffer, cl, i);
	      do_pwd(cl[i].socket, cl[i].name, cl[i].directory);
	      memset(buffer, 0, rc);
	    }
	  break;
	}
    }
}

int			main(int argc, char **argv)
{
  int                   client_length;
  int			port;
  struct sockaddr_in    client;
  int			sok;
  t_infos_server	server;

  if (argc != 2)
    {
      dprintf(2, "usage : ./server [port]\n");
      return (EXIT_FAILURE);
    }
  else
    {
      port = atoi(argv[1]);
      client_length = sizeof(client);
      sok = init_connection(port);
      server.nb_clients = 0;
      server.size_client = client_length;
      server.sock_server = sok;
      launch_server(&server);
    }
  return (EXIT_SUCCESS);
}

int                     launch_server(t_infos_server *server)
{
  t_infos_client	cl[512];
  fd_set		readfs;

   while (1)
    {
      FD_ZERO(&readfs);
      FD_SET(server->sock_server, &readfs);
      for (int i = 0; i < server->nb_clients; i++)
	FD_SET(cl[i].socket, &readfs);
      if (select(max_sok + 1, &readfs, NULL, NULL, NULL) == -1)
	{
	  perror("select");
	  return (EXIT_FAILURE);
	}
      if (FD_ISSET(server->sock_server, &readfs))
	connection_new_client(cl, server, &readfs);
      else
	begin_loop(server, &readfs, cl);
    }
  close(server->sock_server);
  return (EXIT_SUCCESS);
}
