/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   gen_icmp_msg.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/27 19:20:21 by agrumbac          #+#    #+#             */
/*   Updated: 2019/01/31 07:56:35 by agrumbac         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_traceroute.h"

#ifdef __linux__

static void	fill_icmp_header(struct icmphdr *ping, uint16_t id, uint16_t seq)
{
	ping->type = ICMP_ECHO;
	ping->code = 0;
	ping->un.echo.id = htons(id);
	ping->un.echo.sequence = htons(seq);
	ping->checksum = 0;
	ping->checksum = in_cksum(ping, ICMP_PAYLOAD_SIZE + ICMP_HDR_SIZE);
}

#elif __APPLE__

static void	fill_icmp_header(struct icmp *ping, uint16_t id, uint16_t seq)
{
	ping->icmp_type = ICMP_ECHO;
	ping->icmp_code = 0;
	ping->icmp_id = htons(id);
	ping->icmp_seq = htons(seq);
	ping->icmp_cksum = 0;
	ping->icmp_cksum = in_cksum(ping, ICMP_PAYLOAD_SIZE + ICMP_HDR_SIZE);
}

#endif

static void	fill_timestamp(void *buffer)
{
	if (gettimeofday(buffer, NULL) == -1)
		warn("failed getting time of day");
}

static void	fill_payload_ttl(void *buffer, uint8_t ttl, size_t size)
{
	memset(buffer, ttl, size);
}

void		gen_icmp_msg(void *packet, uint16_t seq, uint8_t ttl)
{
	fill_payload_ttl(packet + ICMP_HDR_SIZE, ttl, ICMP_PAYLOAD_SIZE);
	fill_timestamp(packet + ICMP_HDR_SIZE + ALIGN_TIMESTAMP);
	fill_icmp_header(packet, ttl, seq);
}
