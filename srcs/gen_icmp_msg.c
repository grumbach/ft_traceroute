/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   gen_icmp_msg.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/27 19:20:21 by agrumbac          #+#    #+#             */
/*   Updated: 2019/01/31 08:51:21 by agrumbac         ###   ########.fr       */
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

static void	fill_icmp_payload(void *buffer, size_t size)
{
	memset(buffer, 42, size);
}

void		gen_icmp_msg(void *packet, uint16_t seq, uint8_t ttl)
{
	fill_icmp_payload(packet + ICMP_HDR_SIZE, ICMP_PAYLOAD_SIZE);
	fill_icmp_header(packet, ttl, seq);
}
