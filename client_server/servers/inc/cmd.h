/*
** cmd.h for cmd in /home/leguen_q/norme_server/servers/inc
** 
** Made by Quentin Leguen
** Login   <leguen_q@epitech.net>
** 
** Started on  Mon Jul 21 17:02:34 2014 Quentin Leguen
** Last update Wed Jul 23 19:29:32 2014 Quentin Leguen
*/

#ifndef CMD_H_
# define CMD_H_

#include "server.h"

typedef	struct	s_cmd_fptr
{
  char		*cmd;
  int		(*fptr)(int, char *, char *);
}		t_cmd_fptr;

int		check_path(char *, char *, int);
int		match_cmd(char *, t_infos_client *, int);
int		do_cp(int, char *, char *);
int		do_rm(int, char *, char *);
int		do_mkdir(int, char *, char *);
int		do_ls(int, char *, char *);
int		do_mv(int, char *, char *);
int		do_cd(int, char *, char *);
int		do_rmdir(int, char *, char *);
int		do_pwd(int, char *, char *);
int		do_touch(int, char *, char *);

#endif /* !CMD_H_ */
