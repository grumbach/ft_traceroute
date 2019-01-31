/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_traceroute.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/04 18:04:47 by agrumbac          #+#    #+#             */
/*   Updated: 2019/01/31 08:41:32 by agrumbac         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_traceroute.h"
#include <arpa/inet.h> // tmp for inet_addr

static void		send_loop(int sock, const struct sockaddr_in *dest, \
					suseconds_t timestamps[TRC_MAX_TTL][TRC_QUERIES])
{
	char		packet[SENT_PACKET_SIZE];

	for (uint8_t ttl = 1; ttl < TRC_MAX_TTL; ttl++)
	{
		for (uint16_t query = 0; query < TRC_QUERIES; query++)
		{
			gen_ip_header(packet, ttl, dest->sin_addr.s_addr);
			gen_icmp_msg(packet + IP_HDR_SIZE, query, ttl);
			send_echo_request(sock, (const struct sockaddr *)dest, packet, false);
			timestamps[ttl][query] = get_time();
		}
	}
}

static void		recv_loop(int sock, struct sockaddr_in source, \
					suseconds_t timestamps[TRC_MAX_TTL][TRC_QUERIES], \
					char buf[TRC_MAX_TTL][BUFFSIZE])
{
	char				packet[RECV_PACKET_SIZE];
	struct timeval		timeout = {.tv_sec = TRC_TIMEOUT};
	fd_set				set;
	int					ret;

	for (size_t i = 0; i < TRC_MAX_TTL; i++)
	{
		FD_ZERO(&set);
		FD_SET(sock, &set);
		if ((ret = select(sock + 1, &set, NULL, NULL, &timeout)) == -1)
			warn("select refused to comply");
		if (FD_ISSET(sock, &set))
		{
			receive_echo_reply(sock, (struct sockaddr *)&source, packet, false);
			analyse_packet(packet, false, timestamps, buf);
		}
	}
}

static void		flush_last_lines(char buffer[TRC_MAX_TTL][BUFFSIZE])
{
	for (size_t i = 0; i < TRC_MAX_TTL; i++)
		printf("%s", buffer[i]);
}

/*
** out_of_order_packets is static because
**  - it can get big, so might as well put it in BSS
**  - it needs to be filled with zeros, doing it during runtime is ridiculous
*/

int				main(int ac, char **av)
{
	static char			out_of_order_packets[TRC_MAX_TTL][BUFFSIZE];
	static suseconds_t	timestamps[TRC_MAX_TTL][TRC_QUERIES];
	struct sockaddr_in	host_addr = {.sin_family = AF_INET};
	int					sock;

	if (ac != 2)
	{
		dprintf(2, "Usage: %s destination\n", av[0]);
		return (EXIT_FAILURE);
	}

	host_addr.sin_addr.s_addr = inet_addr(av[1]);
	sock = init_socket();

	send_loop(sock, &host_addr, timestamps);
	recv_loop(sock, host_addr, timestamps, out_of_order_packets);
	flush_last_lines(out_of_order_packets);

	return (0);
}
