/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_traceroute.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/04 18:04:47 by agrumbac          #+#    #+#             */
/*   Updated: 2019/01/26 19:35:52 by Anselme          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_traceroute.h"
#include <arpa/inet.h> // tmp for inet_addr
#include <unistd.h> // tmp for sleep

int		main(int ac, char **av)
{
	char				packet[PACKET_SIZE];
	struct sockaddr_in	dest = {.sin_family = AF_INET};
	int					sock;
	u_int8_t			ttl;

	if (ac != 2)
	{
		dprintf(2, "Usage: %s destination\n", av[0]);
		return (EXIT_FAILURE);
	}

	dest.sin_addr.s_addr = inet_addr(av[1]);
	sock = init_socket();
	ttl = 1;

	while (true)
	{
		setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
		gen_icmp_msg(packet, ttl);
		send_echo_request(sock, (struct sockaddr *)&dest, packet, false);
		receive_echo_reply(sock, (struct sockaddr *)&dest, packet, true);

		sleep(1);

		ttl++;
	}

	return (0);
}
