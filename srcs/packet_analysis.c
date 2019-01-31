/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   packet_analysis.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/01/28 02:39:28 by agrumbac          #+#    #+#             */
/*   Updated: 2019/01/31 07:27:53 by agrumbac         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_traceroute.h"

/*
** Utilities
*/

static char			*net_ntoa(uint32_t in)
{
	static char		buffer[18];
	unsigned char	*bytes = (unsigned char *) &in;

	snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d", \
		bytes[0], bytes[1], bytes[2], bytes[3]);

	return (buffer);
}

static suseconds_t	get_time(void)
{
	struct timeval	curr_time;

	if (gettimeofday(&curr_time, NULL) == -1)
	{
		warn("failed getting time of day");
		return (0);
	}
	return (curr_time.tv_sec * 1000000 + curr_time.tv_usec);
}

/*
**------- LINUX ----------------------------------------------------------------
*/

#ifdef __linux__

static uint8_t		get_type(void *packet)
{
	struct icmphdr	*icmp = packet + IP_HDR_SIZE;

	return (icmp->type);
}

static const char	*get_source(void *packet)
{
	struct iphdr	*ip = packet;

	return (net_ntoa(ip->saddr));
}

/*
**------- APPLE ----------------------------------------------------------------
*/

#elif __APPLE__

static uint8_t		get_type(void *packet)
{
	struct icmp		*icmp = packet + IP_HDR_SIZE;

	return (icmp->icmp_type);
}

static const char	*get_source(void *packet)
{
	struct ip		*ip = packet;

	return (net_ntoa(ip->ip_src.s_addr));
}

#endif

/*
**------------------------------------------------------------------------------
*/

static uint8_t		get_payload_ttl(void *packet, uint8_t type)
{
	uint8_t			*payload_ttl;

	if (type == ICMP_TIME_EXCEEDED || type == ICMP_PARAMETERPROB
	||  type == ICMP_SOURCE_QUENCH || type == ICMP_REDIRECT
	||  type == ICMP_TIME_EXCEEDED || type == ICMP_DEST_UNREACH)
		payload_ttl = packet + 2 * IP_HDR_SIZE + 2 * ICMP_HDR_SIZE;
	else
		payload_ttl = packet + IP_HDR_SIZE + ICMP_HDR_SIZE;

	return (*payload_ttl);
}

static suseconds_t	get_payload_rtt(void *packet, uint8_t type)
{
	struct timeval	*send_time;
	struct timeval	aligned_buffer;
	suseconds_t		curr_time = get_time();

	if (type == ICMP_TIME_EXCEEDED || type == ICMP_PARAMETERPROB
	||  type == ICMP_SOURCE_QUENCH || type == ICMP_REDIRECT
	||  type == ICMP_TIME_EXCEEDED || type == ICMP_DEST_UNREACH)
	{
		send_time = packet + 2 * IP_HDR_SIZE + 2 * ICMP_HDR_SIZE + ALIGN_TIMESTAMP;
		memcpy(&aligned_buffer, send_time, sizeof(struct timeval));
		send_time = &aligned_buffer;
	}
	else
		send_time = packet + IP_HDR_SIZE + ICMP_HDR_SIZE + ALIGN_TIMESTAMP;

	return (curr_time - send_time->tv_sec * 1000000 - send_time->tv_usec);
}

/*
** analyse_packet
**  - prints arriving packets info
**  - stores in buf if out of order
*/

void				analyse_packet(void *packet, bool verbose_mode, \
						char buf[FT_TRACEROUTE_MAX_TTL][BUFFSIZE])
{
	static uint8_t	last_ack_ttl = 1;
	static uint8_t	first_echo_reply_ttl = FT_TRACEROUTE_MAX_TTL;
	suseconds_t		rtt;
	uint8_t			ttl;
	uint8_t			type;

	type = get_type(packet);
	ttl = get_payload_ttl(packet, type);
	rtt = get_payload_rtt(packet, type);

	if (verbose_mode)
		dump_reply(packet, type);

	// remember first echo reply's ttl
	if (type == ICMP_ECHOREPLY && ttl < first_echo_reply_ttl)
		first_echo_reply_ttl = ttl;

	// directly print if ttl is invalid
	if (ttl >= FT_TRACEROUTE_MAX_TTL)
		printf("    %-16s (ICMP %2hhu)\n", get_source(packet), type);

	// skip if ttl is greater than found host
	if (ttl > first_echo_reply_ttl)
		return ;

	// if packet arrives out of order store for later else print
	if (ttl != last_ack_ttl)
		snprintf(buf[ttl], BUFFSIZE, "%2hhu  %-16s (ICMP %2hhu) %ld.%02ld ms\n", \
			ttl, get_source(packet), type, rtt / 1000l, rtt % 1000l);
	else
		printf("%2hhu  %-16s (ICMP %2hhu) %ld.%02ld ms\n", last_ack_ttl++, \
			get_source(packet), type, rtt / 1000l, rtt % 1000l);
}
