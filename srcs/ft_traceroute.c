/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_traceroute.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/04 18:04:47 by agrumbac          #+#    #+#             */
/*   Updated: 2019/01/28 08:51:52 by agrumbac         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_traceroute.h"
#include <arpa/inet.h> // tmp for inet_addr

static void		recv_loop(int sock, struct sockaddr_in source)
{
	char				packet[PACKET_SIZE];
	struct timeval		timeout = {.tv_sec = FT_TRACEROUTE_TIMEOUT};
	fd_set				set;
	int					ret;
	uint8_t				ttl;
	uint8_t				type;

	type = ICMP_TIME_EXCEEDED;
	ttl = 0;
	while (type == ICMP_TIME_EXCEEDED && ttl < FT_TRACEROUTE_MAX_TTL)
	{
		// recv or timeout
		FD_ZERO(&set);
		FD_SET(sock, &set);
		ret = select(sock + 1, &set, NULL, NULL, &timeout);
		if (ret == -1)
			warn("select refused to comply");
		if (FD_ISSET(sock, &set))
		{
			receive_echo_reply(sock, (struct sockaddr *)&source, packet, false);
			type = get_type(packet);

			printf("%hhu - from %s\n", get_payload_ttl(packet), get_source(packet));
		}
		else
			warn("timeout");//TODO tmp

		ttl++;
	}
}

static void		send_loop(int sock, const struct sockaddr_in *dest)
{
	char		packet[PACKET_SIZE];
	uint16_t	query;
	uint8_t		ttl;

	ttl = 0;
	while (ttl < FT_TRACEROUTE_MAX_TTL)
	{
		query = 0;
		while (query < FT_TRACEROUTE_QUERIES)
		{
			// send ICMP_ECHO
			gen_ip_header(packet, ttl, dest->sin_addr.s_addr);
			gen_icmp_msg(packet + IP_HDR_SIZE, query, ttl);
			send_echo_request(sock, (const struct sockaddr *)dest, packet, false);
			query++;
		}
		ttl++;
	}
}

int				main(int ac, char **av)
{
	struct sockaddr_in	host_addr = {.sin_family = AF_INET};
	int					sock;

	if (ac != 2)
	{
		dprintf(2, "Usage: %s destination\n", av[0]);
		return (EXIT_FAILURE);
	}

	host_addr.sin_addr.s_addr = inet_addr(av[1]);
	sock = init_socket();

	send_loop(sock, &host_addr);
	recv_loop(sock, host_addr);

	return (0);
}
