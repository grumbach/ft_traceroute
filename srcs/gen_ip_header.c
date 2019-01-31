/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   gen_ip_header.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/12/12 01:42:56 by agrumbac          #+#    #+#             */
/*   Updated: 2019/01/31 02:48:45 by agrumbac         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_traceroute.h"

#ifdef __linux__

static inline void	fill_ip_header(struct iphdr *ip, uint8_t ttl, uint32_t dest)
{
	ip->version = 4;
	ip->ihl = IP_HDR_SIZE / 4;
	ip->tos = 0;
	ip->tot_len = htons(SENT_PACKET_SIZE);
	ip->id = htons(0);
	ip->frag_off = htons(0);
	ip->ttl = ttl;
	ip->protocol = IPPROTO_ICMP;
	ip->check = 0;
	ip->saddr = INADDR_ANY;
	ip->daddr = dest;
}

#elif __APPLE__

static inline void	fill_ip_header(struct ip *ip, uint8_t ttl, uint32_t dest)
{
	ip->ip_v = 4;
	ip->ip_hl = IP_HDR_SIZE / 4;
	ip->ip_tos = 0;
	ip->ip_len = SENT_PACKET_SIZE;
	ip->ip_id = htons(0);
	ip->ip_off = 0;
	ip->ip_ttl = ttl;
	ip->ip_p = IPPROTO_ICMP;
	ip->ip_sum = 0;
	ip->ip_src.s_addr = INADDR_ANY;
	ip->ip_dst.s_addr = dest;
}

#endif

/*
** gen_ip_header
**   provide dest address in network byte order
*/

void			gen_ip_header(void *packet, uint8_t ttl, uint32_t dest)
{
	fill_ip_header(packet, ttl, dest);
}
