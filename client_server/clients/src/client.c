/*
** client.c for client in /home/leguen_q/tcp/tp_ex
** 
** Made by Quentin Leguen
** Login   <leguen_q@epitech.net>
** 
** Started on  Fri Apr 25 19:16:36 2014 Quentin Leguen
** Last update Thu Jul 24 21:59:09 2014 Quentin Leguen
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
#include "client.h"

int			read_server(int fd, char *buffer)
{
  int			ret_read;

  ret_read = read(fd, buffer, strlen(buffer) -1);
  if (ret_read == -1)
    {
      dprintf(2, "error on read server\n");
    }
  return (ret_read);
}

void                    write_server(int fd, char *buffer, int rc)
{
  int			ret_write;

  ret_write = write(fd, buffer, rc);
  if (ret_write == -1)
    dprintf(2, "error on write server\n");
}

int			init_socket(int port, char *ip)
{
  int			sok;
  struct protoent       *protocol;
  struct sockaddr_in    client;
  int                   ret_connect;

  protocol = getprotobyname("TCP");
  if ((sok = socket(AF_INET, SOCK_STREAM, protocol->p_proto)) == -1)
    dprintf(2, "error open socket\n");
  client.sin_family = AF_INET;
  client.sin_port = htons(port);
  client.sin_addr.s_addr = inet_addr(ip);
  ret_connect = connect(sok, (const struct sockaddr *)&client, sizeof(client));
  if (ret_connect == -1)
    {
      write(2, "error connect socket\n", strlen("error connect socket\n"));
      close(sok);
      exit(EXIT_FAILURE);
    }
  return (sok);
}

int                     main(int argc, char **argv)
{
  int                   port;
  int                   sok;
  int			rc;
  char			buffer[1024];

  rc = 0;
  if (argc != 3)
    {
      write(2, "usage : ./client [ip] [port]",
	    strlen("usage : ./client [ip] [port]"));
      exit(EXIT_FAILURE);
    }
  port = atoi(argv[2]);
  sok = init_socket(port, argv[1]);
  infinite_loop(rc, buffer, sok);
  close(sok);
  return (EXIT_SUCCESS);
}

void			infinite_loop(int rc, char *buffer, int sok)
{
  fd_set		readfs;

  while (1)
    {
      FD_ZERO(&readfs);
      FD_SET(sok, &readfs);
      FD_SET(STDIN_FILENO, &readfs);
      if (select(sok + 1, &readfs, NULL, NULL, NULL) == -1)
        dprintf(2, "error on select client\n");
      if (FD_ISSET(STDIN_FILENO, &readfs))
	{
	  if ((rc = read(0, buffer, 1023)) <= 0)
	    memset(buffer, '\0', rc);
	  write(sok, buffer, rc);
	}
      if (FD_ISSET(sok, &readfs))
	{
	  if ((rc = read_server(sok, buffer)) <= 0)
	    {
	      dprintf(2, "server disconnected\n");
	      exit(EXIT_FAILURE);
	    }
	  write(1, buffer, rc);
	}
    }
}
