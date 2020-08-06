#!/bin/bash

# Secure WireGuard server installer for Debian, Ubuntu, CentOS, Fedora and Arch Linux
# https://github.com/angristan/wireguard-install

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
	if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
	fi

	if [ "$(systemd-detect-virt)" == "lxc" ]; then
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	fi
}

function checkOS() {
	# Check OS version
	if [[ -e /etc/debian_version ]]; then
		source /etc/os-release
		OS="${ID}" # debian or ubuntu
		if [[ -e /etc/debian_version ]]; then
			if [[ ${ID} == "debian" || ${ID} == "raspbian" ]]; then
				if [[ ${VERSION_ID} -ne 10 ]]; then
					echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster"
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/fedora-release ]]; then
		source /etc/os-release
		OS="${ID}"
	elif [[ -e /etc/centos-release ]]; then
		OS=centos
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS or Arch Linux system"
		exit 1
	fi
}

function initialCheck() {
	isRoot
	checkVirt
	checkOS
}

function preInstall() {
	echo "Welcome to the WireGuard installer!"
	echo "I need to ask you a few questions before starting the setup."
	echo ""

	# Detect public IPv4 or IPv6 address and pre-fill for the user
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	read -rp "IPv4 public address: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

	# Detect public interface and pre-fill for the user
	SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
	read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
        
	read -rp "WireGuard interface name: " -e -i wg0 SERVER_WG_NIC
        
	read -rp "Server's WireGuard IPv4: " -e -i 10.0.0.1 SERVER_WG_IPV4

	# Generate random number within private ports range
	SERVER_PORT="51820"
    read -rp "Server's WireGuard port: " -e -i "${SERVER_PORT}" SERVER_PORT

    SERVER_MTU="1420"

	# Adguard DNS by default
	read -rp "First DNS resolver to use for the clients: " -e -i 1.1.1.1 CLIENT_DNS_1
    
	read -rp "Second DNS resolver to use for the clients (optional): " -e -i 1.0.0.1 CLIENT_DNS_2

	echo ""
	echo "Okay, that was all I needed. We are ready to setup your WireGuard server now."
	echo ""
	read -n1 -r -p "Press any key to continue..."
}

function installWireGuard() {
	# Run setup questions first
	preInstall

	# Install WireGuard tools and module
	apt-get update
	apt-get install -y qrencode nano wireguard

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Save WireGuard settings
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_PORT=${SERVER_PORT}
SERVER_MTU=${SERVER_MTU}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}" >/etc/wireguard/params

	# Add server interface
	echo "[Interface]
Address = ${SERVER_WG_IPV4}/24
ListenPort = ${SERVER_PORT}
MTU = ${SERVER_MTU}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

	echo "PostUp = iptables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

	# Enable routing on the server
	echo "net.ipv4.ip_forward = 1" >/etc/sysctl.d/wg.conf

	sysctl --system

	systemctl start "wg-quick@${SERVER_WG_NIC}"
	systemctl enable "wg-quick@${SERVER_WG_NIC}"

	# Check if WireGuard is running
	systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\nWARNING: WireGuard does not seem to be running."
		echo "You can check if WireGuard is running with: systemctl status wg-quick@${SERVER_WG_NIC}"
		echo 'If you get something like "Cannot find device wg0", please reboot!'
	fi

	# newClient
	echo "If you want to add more clients, you simply need to run this script another time!"
	echo ""
	listMenu
}

function newClient() {
    ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

    CLIENT_WG_IPV4="10.0.0."
    read -rp "Client's WireGuard IPv4: " -e -i "$CLIENT_WG_IPV4" CLIENT_WG_IPV4

    # CLIENT_NAME=$(
    #    head /dev/urandom | tr -dc A-Za-z0-9 | head -c 10
    #    echo ''
    #)
	CLIENT_NAME="${CLIENT_WG_IPV4}"

    # Generate key pair for the client
    CLIENT_PRIV_KEY=$(wg genkey)
    CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)

    # Create client file and add the server as a peer
    echo "[Interface]
    PrivateKey = $CLIENT_PRIV_KEY
    Address = $CLIENT_WG_IPV4/24
    DNS = $CLIENT_DNS_1,$CLIENT_DNS_2

    [Peer]
    PublicKey = $SERVER_PUB_KEY
    Endpoint = $ENDPOINT
    AllowedIPs = 0.0.0.0/0" >>"$HOME/$SERVER_WG_NIC-client-$CLIENT_NAME.conf"

    # Add the client as a peer to the server
    echo -e "\n### Client ${CLIENT_NAME}
	[Peer]
    PublicKey = $CLIENT_PUB_KEY
    AllowedIPs = $CLIENT_WG_IPV4/32" >>"/etc/wireguard/$SERVER_WG_NIC.conf"

    systemctl restart "wg-quick@$SERVER_WG_NIC"

    echo -e "\nHere is your client config file as a QR Code:"

    qrencode -t ansiutf8 <"$HOME/$SERVER_WG_NIC-client-$CLIENT_NAME.conf"

    echo "\nIt is also available at $HOME/$SERVER_WG_NIC-client-$CLIENT_NAME.conf"
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	echo ""
	echo "Select the existing client you want to revoke"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# remove generated client file
	rm -f "${HOME}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# restart wireguard to apply changes
	systemctl restart "wg-quick@${SERVER_WG_NIC}"
}

function uninstallWg() {
	checkOS

	systemctl stop "wg-quick@${SERVER_WG_NIC}"
	systemctl disable "wg-quick@${SERVER_WG_NIC}"

	if [[ ${OS} == 'ubuntu' ]]; then
		apt-get autoremove --purge -y wireguard
		add-apt-repository -y -r ppa:wireguard/wireguard
	elif [[ ${OS} == 'debian' ]]; then
		apt-get autoremove --purge -y wireguard
	elif [[ ${OS} == 'fedora' ]]; then
		dnf remove -y wireguard-tools
		if [[ ${VERSION_ID} -lt 32 ]]; then
			dnf remove -y wireguard-dkms
			dnf copr disable -y jdoss/wireguard
		fi
		dnf autoremove -y
	elif [[ ${OS} == 'centos' ]]; then
		yum -y remove wireguard-dkms wireguard-tools
		rm -f "/etc/yum.repos.d/wireguard.repo"
		yum -y autoremove
	elif [[ ${OS} == 'arch' ]]; then
		pacman -Rs --noconfirm wireguard-tools
	fi

	rm -rf /etc/wireguard
	rm -f /etc/sysctl.d/wg.conf

	# Reload sysctl
	sysctl --system

	# Check if WireGuard is running
	systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	WG_RUNNING=$?

	if [[ ${WG_RUNNING} -eq 0 ]]; then
		echo "WireGuard failed to uninstall properly."
		exit 1
	else
		echo "WireGuard uninstalled successfully."
		exit 0
	fi
}

function listMenu() {
	echo "What do you want to do?"
	echo "   1) Add a new client"
	echo "   2) Revoke existing client"
	echo "   3) Uninstall WireGuard"
	echo "   4) Exit"
	until [[ ${MENU_OPTION} =~ ^[1-4]$ ]]; do
		read -rp "Select an option [1-4]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		newClient
		;;
	2)
		revokeClient
		;;
	3)
		# uninstallWg
		;;
	4)
		exit 0
		;;
	esac
}

# Check for root, virt, OS...
initialCheck

# Check if WireGuard is already installed and load params
if [[ -e /etc/wireguard/params ]]; then
	source /etc/wireguard/params
	listMenu
else
	installWireGuard
fi