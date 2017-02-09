##
## Makefile for Makefile in /home/leguen_q/tcp/tp_ex
## 
## Made by Quentin Leguen
## Login   <leguen_q@epitech.net>
## 
## Started on  Sun Apr 27 22:12:39 2014 Quentin Leguen
## Last update Thu Jul 24 22:06:59 2014 Quentin Leguen
##

SRC_SERVER=		servers/src/server.c \
			servers/src/send.c \
			servers/src/server2.c \
			servers/src/cmd.c \
			servers/src/send2.c \
			servers/src/cmd2.c \
			servers/src/deco.c \
			servers/src/cmd3.c

SRC_CLIENT=		clients/src/client.c


NAME_SERVER=		server
NAME_CLIENT=		client

OBJ_SERVER=		$(SRC_SERVER:.c=.o)
OBJ_CLIENT=		$(SRC_CLIENT:.c=.o)

CC=			gcc -std=gnu99 -Wall -Wextra -Werror -I./servers/inc -I./clients/inc 

RM=			rm -f

all:			$(NAME_SERVER)	$(NAME_CLIENT)	

$(NAME_SERVER):		$(OBJ_SERVER) 
			$(CC) -o $(NAME_SERVER) $(OBJ_SERVER) 

$(NAME_CLIENT):		$(OBJ_CLIENT)
			$(CC) -o $(NAME_CLIENT) $(OBJ_CLIENT) 

clean:		
			$(RM) $(OBJ_SERVER) $(OBJ_CLIENT)

fclean:			clean
			$(RM) $(NAME_SERVER) $(NAME_CLIENT)

re:			fclean all
