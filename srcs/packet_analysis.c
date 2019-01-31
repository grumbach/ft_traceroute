/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   packet_analysis.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/01/28 02:39:28 by agrumbac          #+#    #+#             */
/*   Updated: 2019/01/31 09:31:46 by agrumbac         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_traceroute.h"

/*
** ---------------- LOADS OF getters for Apple and Linux -----------------------
*/

static void			*get_original_icmphdr(void *packet, uint8_t type)
{
	if (type == ICMP_TIME_EXCEEDED || type == ICMP_PARAMETERPROB
	||  type == ICMP_SOURCE_QUENCH || type == ICMP_REDIRECT
	||  type == ICMP_TIME_EXCEEDED || type == ICMP_DEST_UNREACH)
		return (packet + 2 * IP_HDR_SIZE + ICMP_HDR_SIZE);
	else
		return (packet + IP_HDR_SIZE);
}

static suseconds_t	get_rtt(suseconds_t timestamps[TRC_MAX_TTL][TRC_QUERIES], \
						uint8_t ttl, uint16_t seq)
{
	suseconds_t		curr_time = get_time();

	if (ttl < TRC_MAX_TTL && seq < TRC_QUERIES)
		return (curr_time - timestamps[ttl][seq]);
	return (0);
}

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

static uint16_t		get_original_seq(void *packet, uint8_t type)
{
	struct icmphdr	*icmp = get_original_icmphdr(packet, type);

	return (ntohs(icmp->un.echo.sequence));
}

static uint8_t		get_original_ttl(void *packet, uint8_t type)
{
	struct icmphdr	*icmp = get_original_icmphdr(packet, type);

	return (ntohs(icmp->un.echo.id));
}

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

static uint16_t		get_original_seq(void *packet, uint8_t type)
{
	struct icmp		*icmp = get_original_icmphdr(packet, type);

	return (ntohs(icmp->icmp_seq));
}

static uint8_t		get_original_ttl(void *packet, uint8_t type)
{
	struct icmp		*icmp = get_original_icmphdr(packet, type);

	return (ntohs(icmp->icmp_id));
}

#endif

/*
**------------------------------------------------------------------------------
*/

/*
** analyse_packet
**  - prints arriving packets info
**  - stores in buf if out of order
*/

void				analyse_packet(void *packet, bool verbose_mode, \
						suseconds_t timestamps[TRC_MAX_TTL][TRC_QUERIES], \
						char buf[TRC_MAX_TTL][BUFFSIZE])
{
	static uint8_t	last_ack_ttl = 1;
	static uint8_t	first_echo_reply_ttl = TRC_MAX_TTL - 1;
	suseconds_t		rtt;
	uint16_t		seq;
	uint8_t			ttl;
	uint8_t			type;

	type = get_type(packet);
	ttl = get_original_ttl(packet, type);
	seq = get_original_seq(packet, type);
	rtt = get_rtt(timestamps, ttl, seq);

	if (verbose_mode)
		dump_reply(packet, type);

	// remember first echo reply's ttl
	if (type == ICMP_ECHOREPLY && ttl < first_echo_reply_ttl)
		first_echo_reply_ttl = ttl;

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
