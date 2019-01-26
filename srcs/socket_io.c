/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   socket_io.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/01/18 19:52:51 by agrumbac          #+#    #+#             */
/*   Updated: 2019/01/26 17:48:01 by Anselme          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_traceroute.h"

int		init_socket(void)
{
	int					icmp_sock;

	icmp_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	if (icmp_sock < 0)
	{
		warn("failed opening DGRAM ICMP socket, trying raw...");
		icmp_sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (icmp_sock < 0)
			fatal("failed opening ICMP socket");
	}

	return (icmp_sock);
}

void	send_echo_request(int icmp_sock, const struct sockaddr *dest, \
				char *packet, bool verbose_mode)
{
	ssize_t	ret;

	ret = sendto(icmp_sock, packet, PACKET_SIZE, 0, dest, sizeof(*dest));
	if (ret == -1)
		warn("sendto failed");

	if (verbose_mode)
	{
		printf("sending request:\n");
		print_icmp_packet(packet);
	}
}

void	receive_echo_reply(int icmp_sock, struct sockaddr *source, \
			char *packet, bool verbose_mode)
{
	ssize_t		ret;
	socklen_t	addr_size = sizeof(*source);

	ret = recvfrom(icmp_sock, packet, PACKET_SIZE, 0, source, &addr_size);
	if (ret == -1)
		warn("recvfrom failed");

	if (verbose_mode)
	{
		printf("recieved answer:\n");
		print_icmp_packet(packet);
	}
}
