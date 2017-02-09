/*
** server.h for server in /home/leguen_q/tcp/tp_ex
** 
** Made by Quentin Leguen
** Login   <leguen_q@epitech.net>
** 
** Started on  Fri Apr 25 19:12:34 2014 Quentin Leguen
** Last update Thu Jul 24 22:41:33 2014 Quentin Leguen
*/

#ifndef SERVER_H_ 
# define SERVER_H_

typedef struct	s_infos_client
{
  int		socket;
  char		*name;
  char		*directory;
  char		*current_directory;
  char		*path_base;
  int		current_dir;
  int		first_co;
}               t_infos_client;

typedef struct s_infos_server
{
  int		nb_clients;
  int		size_client;
  int		sock_server;
}		t_infos_server;

int             create_user(char *_getcwd, int sok, t_infos_client *cl, int i);
int             already_exist(int sok, char *_getcwd, t_infos_client *cl, int i, int fd);
char            *create_direct(t_infos_client *cl, int i);
int             create_dir(char *str, int size);
int             ret_max(int nb, t_infos_client *cl);
int		create_file_user(int, int, int, t_infos_client *);
char		*create_pwd();
int		login(int, t_infos_client *, int);
void		begin_loop(t_infos_server *server, fd_set *readfs, t_infos_client *cl);
char		*read_client(int fd);
int		send_msg_clients(t_infos_client *cl, t_infos_server *server, 
				 char *msg, int rc, int actual_client);
int		main(int argc, char **argv);
void		init_client(t_infos_client *cl, int );
void            send_msg_dc(t_infos_client *cl, int nb_clients);
void            aff_tab(t_infos_client *cl, int length);
void            del_client_tab(t_infos_client *cl, int cpt, t_infos_server *server);
void            dc_client(int fd);
void            do_cmd(t_infos_client *cl, char *cmd, int current, 
		       int nb_clients);
void            attribute_name(t_infos_client *cl, char *cmd, int cpt, 
			       int current);
void            join_channel(t_infos_client *cl, char *cmd, int cpt, 
			     int current, int nb_clients);
void            list_channel(t_infos_client *cl, char *cmd, int cpt, 
			     int current);
int		connection_new_client(t_infos_client *cl, t_infos_server *server, fd_set *readfs);
int		launch_server(t_infos_server *server);

#endif /* !SERVER_H_ */
