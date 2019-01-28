/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_traceroute.h                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/04 18:05:58 by agrumbac          #+#    #+#             */
/*   Updated: 2019/01/28 09:19:46 by agrumbac         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_TRACEROUTE_H
# define FT_TRACEROUTE_H

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <stdbool.h>
# include <unistd.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <sys/types.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>

# define __unused				__attribute__((unused))
# define __noreturn				__attribute__((noreturn))
# define __warn_unused_result	__attribute__((warn_unused_result))

# ifdef __APPLE__
#  define ICMP_TIME_EXCEEDED	ICMP_TIMXCEED
# endif

/*
**
*/

# define IP_HDR_SIZE			20
# define ICMP_HDR_SIZE			ICMP_MINLEN
# define ICMP_PAYLOAD_SIZE		56
# define PACKET_SIZE			(IP_HDR_SIZE + ICMP_HDR_SIZE + ICMP_PAYLOAD_SIZE)
# define ALIGN_TIMESTAMP		4

# define FT_TRACEROUTE_TIMEOUT	5
# define FT_TRACEROUTE_MAX_TTL	30
# define FT_TRACEROUTE_QUERIES	1

/*
** Socket i/o
*/

int				init_socket(void);
void			send_echo_request(int icmp_sock, const struct sockaddr *dest, \
					char *packet, bool verbose_mode);
void			receive_echo_reply(int icmp_sock, struct sockaddr *source, \
					char *packet, bool verbose_mode);

/*
** Packet creation and analysis
*/

void			gen_icmp_msg(void *packet, uint16_t seq, uint8_t ttl);
void			gen_ip_header(void *packet, uint8_t ttl, uint32_t dest);
uint16_t		in_cksum(const void *buffer, size_t size);

uint8_t			get_type(void *packet);
const char		*get_source(void *packet);
uint8_t			get_payload_ttl(void *packet);

/*
** Verbose mode and error announcing
*/

void			print_ip_icmp_packet(void *packet);

void			fatal(const char * const message);
void			warn(const char * const message);

#endif
