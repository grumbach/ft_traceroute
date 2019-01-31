/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_traceroute.h                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/04 18:05:58 by agrumbac          #+#    #+#             */
/*   Updated: 2019/01/31 11:01:11 by agrumbac         ###   ########.fr       */
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
# include <netdb.h>

/*
** Redefinition of mainstream MACROS
*/

# define __unused				__attribute__((unused))
# define __noreturn				__attribute__((noreturn))
# define __warn_unused_result	__attribute__((warn_unused_result))

# ifdef __APPLE__
#  define ICMP_DEST_UNREACH     ICMP_UNREACH
#  define ICMP_SOURCE_QUENCH    ICMP_SOURCEQUENCH
#  define ICMP_TIME_EXCEEDED    ICMP_TIMXCEED
#  define ICMP_PARAMETERPROB    ICMP_PARAMPROB
#  define ICMP_TIMESTAMP        ICMP_TSTAMP
#  define ICMP_TIMESTAMPREPLY   ICMP_TSTAMPREPLY
#  define ICMP_INFO_REQUEST     ICMP_IREQ
#  define ICMP_INFO_REPLY       ICMP_IREQREPLY
#  define ICMP_ADDRESS          ICMP_MASKREQ
#  define ICMP_ADDRESSREPLY     ICMP_MASKREPLY
# endif

/*
** Traceroute CONSTANTS
*/

# define IP_HDR_SIZE			20
# define ICMP_HDR_SIZE			ICMP_MINLEN
# define ICMP_PAYLOAD_SIZE		32
# define SENT_PACKET_SIZE		(IP_HDR_SIZE + ICMP_HDR_SIZE + ICMP_PAYLOAD_SIZE)
# define RECV_PACKET_SIZE		(IP_HDR_SIZE + ICMP_HDR_SIZE + IP_HDR_SIZE + ICMP_HDR_SIZE+ ICMP_PAYLOAD_SIZE)
# define ALIGN_TIMESTAMP		4
# define BUFFSIZE				128

# define TRC_TIMEOUT			6
# define TRC_MAX_TTL			30
# define TRC_QUERIES			3
# define TRC_ACK_WINDOW			8

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

void			analyse_packet(void *packet, bool verbose_mode, \
					suseconds_t timestamps[TRC_MAX_TTL][TRC_QUERIES], \
					char buf[TRC_MAX_TTL][BUFFSIZE]);

/*
** Utilities
*/

suseconds_t		get_time(void);
char			*net_ntoa(uint32_t in);
uint16_t		in_cksum(const void *buffer, size_t size);

/*
** Verbose mode and error announcing
*/

void			dump_reply(void *packet, uint8_t type);
void			print_ip_icmp_packet(void *packet);

void			fatal(const char * const message);
void			warn(const char * const message);

#endif
