/*
** cmd2.c for boite in /home/leguen_q/norme_server/servers/src
** 
** Made by Quentin Leguen
** Login   <leguen_q@epitech.net>
** 
** Started on  Thu Jul 24 20:47:58 2014 Quentin Leguen
** Last update Thu Jul 24 21:55:07 2014 Quentin Leguen
*/

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "cmd.h"

int             do_cp(int sok, __attribute__((unused))char *name_file,
		      char *path)
{
  pid_t         pid;
  char          arg1[1024];
  char          arg2[1024];
  int           rc;

  send(sok, "enter first arg : ", strlen("enter first arg : "), MSG_NOSIGNAL);
  rc = read(sok, arg1, 1023);
  arg1[rc -1] = '\0';
  if (check_path(arg1, path, sok) == EXIT_FAILURE)
    return (EXIT_FAILURE);
  send(sok, "enter scnd arg : ", strlen("enter scnd arg : "), MSG_NOSIGNAL);
  rc = read(sok, arg2, 1023);
  arg2[rc - 1] = '\0';
  if (check_path(arg2, path, sok) == EXIT_FAILURE)
    return (EXIT_FAILURE);
  if ((pid = fork()) == 0)
    {
      dup2(sok, 1);
      execlp("cp", "cp", arg1, arg2, NULL);
    }
  else if (pid == -1)
    return (EXIT_FAILURE);
  else
    wait(NULL);
  return (EXIT_SUCCESS);
}

int             do_rm(int sok, __attribute__((unused))char *name_file,
		      char *path)
{
  pid_t         pid;
  char          arg[1024];
  int           rc;

  send(sok, "enter arg : ", strlen("enter arg : "), MSG_NOSIGNAL);
  if ((rc = read(sok, arg, 1023)) == -1)
    return (EXIT_FAILURE);
  arg[rc - 1] = '\0';
  if (check_path(arg, path, sok) == EXIT_FAILURE)
    return (EXIT_FAILURE);
  if ((pid = fork()) == 0)
    {
      dup2(sok, 1);
      if (execlp("rm", "rm", arg, NULL) == -1)
	return (EXIT_FAILURE);
    }
  else if (pid == -1)
    return (EXIT_FAILURE);
  else
    wait(NULL);
  return (EXIT_SUCCESS);
}

int             do_rmdir(int sok, __attribute__((unused))char *name_client,
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
      if (execlp("rmdir", "rmdir", arg, NULL) == -1)
	return (EXIT_FAILURE);
    }
  else if (pid == -1)
    return (EXIT_FAILURE);
  else
    wait(NULL);
  return (EXIT_SUCCESS);
}

int             do_ls(int sok, __attribute__((unused))char *name_client,
		      char *path)
{
  pid_t         pid;
  char          _getcwd[1024];

  getcwd(_getcwd, 1023);
  if (check_path(_getcwd, path, sok) == EXIT_FAILURE)
    return (EXIT_FAILURE);
  if ((pid = fork()) == 0)
    {
      dup2(sok, 1);
      if (execlp("ls", "ls", "-la", NULL) == -1)
	return (EXIT_FAILURE);
    }
  else if (pid == -1)
    return (EXIT_FAILURE);
  else
    wait(NULL);
  return (EXIT_SUCCESS);
}

int             do_mkdir(int sok, __attribute__((unused))char *name_client,
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
      if (execlp("mkdir", "mkdir", arg, NULL) == -1)
	return (EXIT_FAILURE);
    }
  else if (pid == -1)
    return (EXIT_FAILURE);
  else
    wait(NULL);
  return (EXIT_SUCCESS);
}
