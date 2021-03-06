/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utilities.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: agrumbac <agrumbac@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/23 20:07:34 by agrumbac          #+#    #+#             */
/*   Updated: 2019/01/31 09:31:10 by agrumbac         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_traceroute.h"

/*
** Utilities
*/

char				*net_ntoa(uint32_t in)
{
	static char		buffer[18];
	unsigned char	*bytes = (unsigned char *) &in;

	snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d", \
		bytes[0], bytes[1], bytes[2], bytes[3]);

	return (buffer);
}

suseconds_t			get_time(void)
{
	struct timeval	curr_time;

	if (gettimeofday(&curr_time, NULL) == -1)
	{
		warn("failed getting time of day");
		return (0);
	}
	return (curr_time.tv_sec * 1000000 + curr_time.tv_usec);
}

/*
** Muhahahahahaha! >:D-
** (don't do this at home)
*/

uint16_t		in_cksum(__unused const void *buffer, __unused size_t size)
{
	asm volatile (".intel_syntax;\n"
			"  xor rax, rax\n"
			"  cmp rsi, 0x1\n"
			"  jne _loop\n"
			"_odd_case:\n"
			"  xor rdx, rdx\n"
			"  mov dl , BYTE PTR [rdi]\n"
			"  sub rsi, 1\n"
			"  jmp _add_cksum\n"
			"_loop:\n"
			"  xor rdx, rdx\n"
			"  mov dx, WORD PTR [rdi]\n"
			"  add rdi, 2\n"
			"  sub rsi, 2\n"
			"_add_cksum:\n"
			"  add rax, rdx\n"
			"  cmp rsi, 1\n"
			"  jg _loop\n"
			"  je _odd_case\n"
			"  mov rcx, rax\n"
			"  shr rcx, 16\n"
			"  and rax, 0xffff\n"
			"  add rax, rcx\n"
			"  mov rcx, rax\n"
			"  shr rcx, 16\n"
			"  add rax, rcx\n"
			"  not rax\n"
			"  leave\n"
			"  ret\n");

	__builtin_unreachable();
}
