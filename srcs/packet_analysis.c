/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   packet_analysis.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/01/28 02:39:28 by agrumbac          #+#    #+#             */
/*   Updated: 2019/01/28 08:35:21 by agrumbac         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_traceroute.h"

static char			*net_ntoa(uint32_t in)
{
	static char		buffer[18];
	unsigned char	*bytes = (unsigned char *) &in;

	snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d", \
		bytes[0], bytes[1], bytes[2], bytes[3]);

	return (buffer);
}

#ifdef __linux__

uint8_t			get_type(void *packet)
{
	struct icmphdr	*icmp = packet + IP_HDR_SIZE;

	return (icmp->type);
}

const char		*get_source(void *packet)
{
	struct iphdr	*ip = packet;

	return (net_ntoa(ip->saddr));
}

uint8_t			get_payload_ttl(void *packet)
{
	uint8_t		*payload_ttl = packet + IP_HDR_SIZE + ICMP_HDR_SIZE;

	return (*payload_ttl);
}

#elif __APPLE__

uint8_t			get_type(void *packet)
{
	struct icmp		*icmp = packet + IP_HDR_SIZE;

	return (icmp->icmp_type);
}

const char		*get_source(void *packet)
{
	struct ip		*ip = packet;

	return (net_ntoa(ip->ip_src.s_addr));
}

uint8_t			get_payload_ttl(void *packet)
{
	uint8_t		*payload_ttl = packet + IP_HDR_SIZE + ICMP_HDR_SIZE;

	return (*payload_ttl);
}

#endif
