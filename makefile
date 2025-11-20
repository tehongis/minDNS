minDNS	:	main.c
		gcc -Wall -Wextra -O2 -o minDNS main.c cache.c
		sudo setcap 'cap_net_bind_service=+ep' minDNS
