/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_traceroute.h                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/04 18:05:58 by agrumbac          #+#    #+#             */
/*   Updated: 2019/01/26 18:12:16 by Anselme          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_TRACEROUTE_H
# define FT_TRACEROUTE_H

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <stdbool.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>

# define __unused				__attribute__((unused))
# define __noreturn				__attribute__((noreturn))
# define __warn_unused_result	__attribute__((warn_unused_result))

# define ICMP_HDR_SIZE			ICMP_MINLEN
# define ICMP_PAYLOAD_SIZE		56
# define PACKET_SIZE			(ICMP_HDR_SIZE + ICMP_PAYLOAD_SIZE)
# define ALIGN_TIMESTAMP		4

/*
** Socket i/o
*/

int				init_socket(void);
void			send_echo_request(int icmp_sock, const struct sockaddr *dest, \
					char *packet, bool verbose_mode);
void			receive_echo_reply(int icmp_sock, struct sockaddr *source, \
					char *packet, bool verbose_mode);

/*
** Packet creation
*/

void			gen_icmp_msg(void *packet, int seq);
uint16_t		in_cksum(const void *buffer, size_t size);

/*
** Verbose mode and error announcing
*/

void			print_icmp_packet(void *packet);

void			fatal(const char * const message);
void			warn(const char * const message);

#endif
