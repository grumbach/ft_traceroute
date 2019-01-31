/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print_packet.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/04 18:05:58 by agrumbac          #+#    #+#             */
/*   Updated: 2019/01/31 07:28:44 by agrumbac         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_traceroute.h"

static const char	*packet_format = \
"\e[32m IP HEADER\n" \
"\e[34m+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
"\e[32m| IPv  %1x | IHL %1x |    TOS %3hhx   |       Total Length %-5hx      |\n" \
"\e[34m+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
"\e[32m|      Identification    %04hx   |       Fragment Offset %5hx   |\n" \
"\e[34m+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
"\e[32m|   TTL  %3hhx    |   Protocol %-3hhx|       Header Checksum %04hx    |\n" \
"\e[34m+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
"\e[32m|                     Source Address    %08x                |\n" \
"\e[34m+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
"\e[32m|                  Destination Address  %08x                |\n" \
"\e[34m+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
"\e[32m ICMP HEADER\n" \
"\e[34m+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
"\e[32m|    Type %-3hhx   |    Code %-3hhx   |        Checksum %04hx          |\n" \
"\e[34m+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
"\e[32m|           Identifier %-5x    |        Sequence Number %-5x  |\n" \
"\e[34m+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\e[0m\n";

#ifdef __linux__

void				print_ip_icmp_packet(void *packet)
{
	struct iphdr	*ip = packet;
	struct icmphdr	*icmp = packet + IP_HDR_SIZE;

	printf(packet_format, ip->version, ip->ihl, ip->tos, ntohs(ip->tot_len), \
		ntohs(ip->id), ntohs(ip->frag_off), ip->ttl, ip->protocol, ip->check, \
		ip->saddr, ip->daddr, icmp->type, icmp->code, \
		icmp->checksum, ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
}

#elif __APPLE__

void				print_ip_icmp_packet(void *packet)
{
	struct ip		*ip = packet;
	struct icmp		*icmp = packet + IP_HDR_SIZE;

	printf(packet_format, ip->ip_v, ip->ip_hl, ip->ip_tos, ip->ip_len, \
		ntohs(ip->ip_id), ip->ip_off, ip->ip_ttl, ip->ip_p, ip->ip_sum, \
		ip->ip_src.s_addr, ip->ip_dst.s_addr, icmp->icmp_type, icmp->icmp_code, \
		icmp->icmp_cksum, ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
}

#endif

static void			hexdump(void *addr, int len)
{
	int				i;
	unsigned char	buff[17];
	unsigned char	*pc = (unsigned char*)addr;

	for (i = 0; i < len; i++)
	{
		if ((i % 16) == 0)
		{
			if (i != 0)
			printf ("  %s\n", buff);
			printf ("%04x ", i);
		}
		printf (" %02x", pc[i]);
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
			buff[(i % 16) + 1] = '\0';
	}
	while ((i % 16) != 0)
	{
		printf ("   ");
		i++;
	}
	printf ("  %s\n\n", buff);
}

void				dump_reply(void *packet, uint8_t type)
{
	if (type == ICMP_TIME_EXCEEDED || type == ICMP_PARAMETERPROB
	||  type == ICMP_SOURCE_QUENCH || type == ICMP_REDIRECT
	||  type == ICMP_TIME_EXCEEDED || type == ICMP_DEST_UNREACH)
	{
		print_ip_icmp_packet(packet);
		print_ip_icmp_packet(packet + IP_HDR_SIZE + ICMP_HDR_SIZE);
		hexdump(packet + 2 * IP_HDR_SIZE + 2 * ICMP_HDR_SIZE, ICMP_PAYLOAD_SIZE);
	}
	else
	{
		print_ip_icmp_packet(packet);
		hexdump(packet + IP_HDR_SIZE + ICMP_HDR_SIZE, ICMP_PAYLOAD_SIZE);
	}
}
