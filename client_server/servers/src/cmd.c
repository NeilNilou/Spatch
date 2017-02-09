/*
** cmd.c for cmd in /home/leguen_q/norme_server/servers/src
** 
** Made by Quentin Leguen
** Login   <leguen_q@epitech.net>
** 
** Started on  Mon Jul 21 17:02:02 2014 Quentin Leguen
** Last update Thu Jul 24 21:56:48 2014 Quentin Leguen
*/

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "cmd.h"

t_cmd_fptr	cmd_tab[8] =
{
  {"cp\n", &do_cp},
  {"rm\n", &do_rm},
  {"mkdir\n", &do_mkdir},
  {"ls\n", &do_ls},
  {"mv\n", &do_mv},
  {"rmdir\n", &do_rmdir},
  {"pwd\n", &do_pwd},
  {"touch\n", &do_touch}
};

int		match_cmd(char *str, t_infos_client *cl, int i)
{
  if (cl[i].first_co == 0)
    {
      chdir(cl[i].directory);
      do_pwd(cl[i].socket, cl[i].name, cl[i].directory);
      cl[i].first_co = 1;
    }
  chdir(cl[i].directory);
  for (int cpt = 0; cpt != 8; cpt += 1)
    {
      if (strncmp(str, cmd_tab[cpt].cmd, strlen(str)) == 0)
  	{
  	  dprintf(1, "commande matched\n");
  	  if (cmd_tab[cpt].fptr(cl[i].socket, cl[i].name,
				cl[i].directory) == EXIT_FAILURE)
  	    {
  	      dprintf(1, "the command is not valid, plz try again\n");
  	      return (EXIT_FAILURE);
  	    }
  	  else
  	    return (EXIT_SUCCESS);
  	}
    }
  return (EXIT_SUCCESS);
}

int		do_pwd(int sok, __attribute__((unused))char *name_client,
		       __attribute__((unused))char *path)
{
  char		_getcwd[1024];

  getcwd(_getcwd, 1023);
  send(sok, _getcwd, strlen(_getcwd), MSG_NOSIGNAL);
  send(sok, "\n", 1, MSG_NOSIGNAL);
  return (EXIT_SUCCESS);
}

int		do_mv(int sok, __attribute__((unused))char *name_client, char *path)
{
  pid_t		pid;
  int		rc;
  char		arg1[1024];
  char		arg2[1024];

  send(sok, "enter arg1 : ", strlen("enter arg1 : "), MSG_NOSIGNAL);
  rc = read(sok, arg1, 1023);
  arg1[rc - 1] = '\0';
  if (check_path(arg1, path, sok) == EXIT_FAILURE)
    return (EXIT_FAILURE);
  send(sok, "enter arg2 : ", strlen("enter arg2 : "), MSG_NOSIGNAL);
  rc = read(sok, arg2, 1023);
  arg2[rc - 1] = '\0';
  if (check_path(arg2, path, sok) == EXIT_FAILURE)
    return (EXIT_FAILURE);
  if ((pid = fork()) == 0)
    {
      dup2(sok, 1);
      execlp("mv", "mv", arg1, arg2, NULL);
    }
  else if (pid == -1)
     return (EXIT_FAILURE);
  else
    wait (NULL);
  return (EXIT_SUCCESS);
}

int		check_path(char *arg, __attribute__((unused))char *path, int sok)
{
  if (arg == NULL)
    {
      dprintf(sok, "chaine nulle");
      return (EXIT_FAILURE);
    }
  for (int i = 0; i < (int)strlen(path) ; i++)
    {
      if (path[i] == '.')
	send(sok, "plz enter the full path\n",
	     strlen("plz enter the full path\n"), MSG_NOSIGNAL);
    }
  if (strncmp(path, arg, strlen(path)) == 0)
    return (EXIT_SUCCESS);
  else
    {
      send(sok, "this path is unvaiable for the user\n",
	   strlen("this path is unvaiable for the user\n"), MSG_NOSIGNAL);
      chdir(path);
    }
  return (EXIT_FAILURE);
}
