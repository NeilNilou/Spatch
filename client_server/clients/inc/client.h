/*
** client.h for client in /home/leguen_q/tcp/tp_ex
** 
** Made by Quentin Leguen
** Login   <leguen_q@epitech.net>
** 
** Started on  Fri Apr 25 17:12:51 2014 Quentin Leguen
** Last update Fri Apr 25 19:17:39 2014 Quentin Leguen
*/

#ifndef CLIENT_H_
# define CLIENT_H_

int	read_server(int fd, char *buffer);
void                    write_server(int fd, char *buffer, int rc);
int             init_socket(int port, char *ip);
int                     main(int argc, char **argv);
void            infinite_loop(int rc, char *buffer, int sok);

#endif /* !CLIENT_H_ */
