/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print_packet.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/04 18:05:58 by agrumbac          #+#    #+#             */
/*   Updated: 2019/01/26 19:35:25 by Anselme          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_traceroute.h"

static const char		*packet_format = \
"\e[32m ICMP HEADER\n" \
"\e[34m+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
"\e[32m|    Type %hhx     |    Code %hhx     |        Checksum %04hx          |\n" \
"\e[34m+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n" \
"\e[32m|           Identifier %04x      |        Sequence Number %x      |\n" \
"\e[34m+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\e[0m\n";

#ifdef __linux__

void	print_icmp_packet(void *packet)
{
	struct icmphdr *icmp = packet;

	printf(packet_format, icmp->type, icmp->code, \
		icmp->checksum, ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
}

#elif __APPLE__

void	print_icmp_packet(void *packet)
{
	struct icmp *icmp = packet;

	printf(packet_format, icmp->icmp_type, icmp->icmp_code, \
		icmp->icmp_cksum, ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
}

#endif
