CC	:= gcc

RM	:= rm -rf

LDFLAGS	+= 

CFLAGS	+=

SRCS	:=

OBJS	:= $(SRCS:.c=.o)

NAME	:= Spatch

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) -o $(NAME) $(OBJS) $(LDFLAGS)

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAME)

re: fclean all

.PHONY: all re clean fclean
