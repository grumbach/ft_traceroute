# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2018/04/10 17:19:11 by agrumbac          #+#    #+#              #
#    Updated: 2019/01/31 11:11:00 by agrumbac         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

############################## BIN #############################################

NAME = ft_traceroute

SRC = ft_traceroute.c errors.c gen_icmp_msg.c gen_ip_header.c utilities.c \
	print_packet.c socket_io.c packet_analysis.c

CC = clang

SRCDIR = srcs

OBJDIR = objs

OBJ = $(addprefix ${OBJDIR}/, $(SRC:.c=.o))

DEP = $(addprefix ${OBJDIR}/, $(SRC:.c=.d))

CFLAGS = -Wall -Wextra -Werror -MMD

LDFLAGS = -Iincludes/

############################## COLORS ##########################################

BY = "\033[33;1m"
BR = "\033[31;1m"
BG = "\033[32;1m"
BB = "\033[34;1m"
BM = "\033[35;1m"
BC = "\033[36;1m"
Y = "\033[33m"
R = "\033[31m"
G = "\033[32m"
B = "\033[34m"
M = "\033[35m"
C = "\033[36m"
WR = "\033[0m""\033[31;5m"
WG = "\033[0m""\033[32;5m"
X = "\033[0m"
UP = "\033[A"
CUT = "\033[K"

############################## RULES ###########################################

all: art ${NAME}

${NAME}: ${OBJ}
	@echo ${B}Compiling [${NAME}]...${X}
	@${CC} ${CFLAGS} ${LDFLAGS} ${LIB} -o $@ ${OBJ}
	@echo ${G}Success"   "[${NAME}]${X}

${OBJDIR}/%.o: ${SRCDIR}/%.c ${EXT}
	@echo ${Y}Compiling [$@]...${X}
	@/bin/mkdir -p ${OBJDIR}
	@${CC} ${CFLAGS} ${LDFLAGS} -c -o $@ $<
	@printf ${UP}${CUT}

############################## GENERAL #########################################

clean:
	@echo ${R}Cleaning"  "[objs]...${X}
	@/bin/rm -Rf ${OBJDIR}

fclean: clean
	@echo ${R}Cleaning"  "[${NAME}]...${X}
	@/bin/rm -f ${NAME}
	@/bin/rm -Rf ${NAME}.dSYM

test:
	@${CC} ${LDFLAGS} -g -fsanitize=address,undefined ${LIB} \
	-I. -o ${NAME} $(addprefix srcs/, ${SRC})

re: fclean all

############################## DECORATION ######################################

art:
	@echo ${BB}
	@echo "                           "${WG}".    ."${X}${BB}
	@echo "    \`  ft_traceroute        )  (  "
	@echo "      _ _ _ _ _ _ _ _ _ _ _(.--.)  "
	@echo "  \` ((_(_(_(_(_(_(_(_(_(_(_( "${WR}"'"${X}${BB}"_"${WR}"'"${X}${BB}")  "
	@echo "      \"\" \"\" \"\" \"\" \"\" \"\" \"\" \"' \`\` "
	@echo ${X}

.PHONY: all clean fclean re art

-include ${DEP}
