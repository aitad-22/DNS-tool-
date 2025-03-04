from pkgutil import resolve_name
from pydoc import resolve
from types import resolve_bases
from xml.dom import DOMException
import dns.exception
import dns.resolver
from termcolor import colored
import argparse
import dns.query
import dns.zone
import dns.resolver
import requests
import random
import string
import time
import threading
import socket
from collections import defaultdict, Counter
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape

# Rich Console instance
console = Console()

# Function to get the attacker's geolocation
def get_attacker_location():
    try:
        response = requests.get("https://ipinfo.io")
        data = response.json()
        location = f"{data.get('city', 'Unknown city')}, {data.get('region', 'Unknown region')}, {data.get('country', 'Unknown country')}"
        ip_address = data.get("ip", "Unknown IP")
        console.print(
            Panel(
                f"[bold blue][INFO][/bold blue] Machine's location: [bold]{location}[/] (IP: [cyan]{ip_address}[/])",
                title="[bold yellow] Machine  Location[/bold yellow]",
                border_style="green",
            )
        )
    except requests.exceptions.RequestException as e:
        console.print(f"[red] MACHINE location: {str(e)}[/red]")

# Zone transfer check
def check_zone_transfer(dns_ip, domain):
    console.print(Panel("[+] Performing Zone Transfer check...", title="Zone Transfer Check", border_style="blue"))
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(dns_ip, domain))
        console.print(
            f"[bold yellow][WARNING][/bold yellow] Zone transfer allowed on {dns_ip} for {domain}.",
            style="red",
        )
    except Exception as e:
        console.print(
            f"[bold green][INFO][/bold green] Zone transfer not allowed on {dns_ip} for {domain}: {str(e)}"
        )

# DNSSEC check
def dnssec_check(dns_ip, domain):
    console.print(Panel("[+] Performing DNSSEC check...", title="DNSSEC Check", border_style="blue"))
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [dns_ip]
        response = resolver.resolve(domain, "DNSKEY", raise_on_no_answer=False)
        if response.rrset:
            console.print("[green]😁 DNSSEC is enabled:[/]")
            for rdata in response:
                console.print(f"  - {rdata}")
        else:
            console.print("[red]😞 DNSSEC is not enabled.[/]")
    except Exception as e:
        console.print(f"[red]😵💫 DNSSEC check failed: {e}[/red]")

# Cache snooping check
def cache_snooping_check(dns_ip, domain):
    console.print(Panel("[+] Performing Cache Snooping check...", title="Cache Snooping Check", border_style="blue"))
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns_ip]
    try:
        response = resolver.resolve(domain, "A", raise_on_no_answer=False)
        if response.rrset:
            console.print("[red]😞 Cache Snooping successful:[/]")
            for rdata in response:
                console.print(f"  - [red]{rdata}[/red]")
        else:
            console.print("[green]😁 Cache Snooping not successful.[/green]")
    except Exception as e:
        console.print(f"[red]😵💫 Cache Snooping check failed: {e}[/red]")
# dns  amplification new
def dns_amplification_check(dns_ip,domain):
    console.print(Panel("[+] Performing amplification check...", title=" amplification Check", border_style="blue"))
    query = dns.message.make_query(domain, dns.rdatatype.ANY)
    query.flags |= dns.flags.AD
    query.find_rrset(query.additional, dns.name.root, 65535, dns.rdatatype.OPT, create=True, force_unique=True)
    try:
        response = dns.query.udp(query, dns_ip)
        if len(response.answer) > 0:
            amplification_factor = len(response.to_wire()) / len(query.to_wire())
            console.print(f"[red] 🤦♂ DNS Amplification factor: {amplification_factor}[/red]")    
        else:
            console.print(f"[green] 😁 DNS Amplification check not successful for {domain}[/red]")
            
    except Exception as e:
        console.print(f"[red]😵💫 DNS Amplification check failed for: {escape(str(e))}[/red]")
        
# Wildcard injection check
def wildcard_injections_check(domain):
    console.print(Panel("[+] Performing Wildcard Injection check...", title="Wildcard Injection Check", border_style="blue"))
    random_subdomains = [generate_random_subdomain(domain) for _ in range(3)]
    ips = set()
    for subdomain in random_subdomains:
        try:
            ip = socket.gethostbyname(subdomain)
            ips.add(ip)
        except socket.gaierror:
            pass
    if len(ips) > 1:
        console.print(f"[red]🤦♂ Wildcard injection detected for {domain}[/red]")
        return True
    else:
        console.print(f"[green]😁 No wildcard injection detected for {domain}[/green]")
        return False

# NXDOMAIN attacks check
def nxdomain_attacks_check(domain):
    console.print(Panel("[+] Performing NXDOMAIN Attacks check...", title="NXDOMAIN Check", border_style="blue"))
    resolver = dns.resolver.Resolver()
    random_subdomain = generate_random_subdomain(domain)
    try:
        resolver.resolve(random_subdomain, "A")
    except dns.resolver.NXDOMAIN:
        console.print(f"[green]😁 No NXDOMAIN attack detected for {domain}[/green]")
        return False
    except dns.resolver.NoAnswer:
        console.print(f"[red]🤦♂ NXDOMAIN attack detected for {domain}[/red]")
        return True
    except dns.resolver.Timeout:
        console.print(f"[yellow]DNS query timed out for {domain}[/yellow]")
        return False
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return False
# new
def dns_rebinding_check(dns_ip,domain):
    
    console.print(Panel("[+] Performing DNS Rebinding check...",title="Rebinding Check", border_style="blue"))
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns_ip]
    try:
        response = resolver.resolve(domain, 'A', raise_on_no_answer=False)
        if response.rrset:
            for rdata in response:
                ip = str(rdata)
                if ip.startswith("127.") or ip.startswith("0."):
                    console.print(f"[red] 🤦♂ DNS Rebinding detected for {ip} [/red]")
                    
                else:
                    console.print(f"[green] 😁 DNS Rebinding not detected for {ip} [/green]")
                    
        else:
            console.print(f"[green] 😵💫 DNS Rebinding check not successful [/green]")
            
    except Exception as e:
        console.print(f"[green] 😵💫 DNS Rebinding check failed: {e}")
        
#new
def dns_reflection_check(dns_ip,domain):
    
    console.print(Panel("[+] Performing DNS Reflection check...",title="reflection check",border_style="blue"))
    query = dns.message.make_query(domain, dns.rdatatype.A)
    query.flags |= dns.flags.AD
    query.find_rrset(query.additional, dns.name.root, 65535, dns.rdatatype.OPT, create=True, force_unique=True)
    try:
        response = dns.query.udp(query, dns_ip)
        if len(response.answer) > 0:
            console.print(f"[red] 😞 DNS Reflection detected [/red]")
            for rdata in response.answer:
                print(colored(rdata,'red'))
                
        else:
            console.print(f"[green] 😁 DNS Reflection not detected [/green]")
            
    except Exception as e:
        console.print(f"[red]😵💫 DNS Reflection check failed for {e} [/red]")
        
#new
def open_recursion_check(server):
    
    console.print(Panel("[+] Performing Open Recursion check...",title="recursion check",border_style="blue"))
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server]

    try:
        answers = resolver.resolve('version.bind', 'TXT')
        if answers.response.answer:
            console.print(f"[red] 😞 Open recursion detected on {server} [/red]")
            
            return True
        else:
            console.print(f"[green] 😁 No open recursion detected on {server} [/green]")
            
            return False
    except dns.resolver.NXDOMAIN:
        console.print(f"[red] 😁 Server {server} does not support version.bind [/red]")
        
        return False
    except dns.resolver.Timeout:
        console.print(f"[red] 😁 DNS query timed out for {server} [/red]")
        
        return False
    except Exception as e:
        print(colored(f"Error: {e}",'red'))
        return False

# Generate random subdomains
def generate_random_subdomain(domain, length=10):
    random_str = "".join(random.choices(string.ascii_lowercase, k=length))
    return f"{random_str}.{domain}"

# Main function
def main():
    parser = argparse.ArgumentParser(description="DNS SecurityTool by ADSVY")
    parser.add_argument("dns_ip", help="DNS IP address to assess")
    parser.add_argument("domain", help="Domain to assess along with")
    args = parser.parse_args()

    dns_ip = args.dns_ip
    domain = args.domain

    console.print(
        Panel("[bold magenta]DNS SecurityTool by ADSVY[/bold magenta]", title="Tool Info", border_style="cyan")
    )

    # Get attacker's location
    get_attacker_location()

    # Run the checks
    check_zone_transfer(dns_ip, domain)
    dnssec_check(dns_ip, domain)
    cache_snooping_check(dns_ip, domain)
    wildcard_injections_check(domain)
    dns_amplification_check(dns_ip,domain)
    nxdomain_attacks_check(domain)
    dns_rebinding_check(dns_ip,domain)
    dns_reflection_check(dns_ip,domain)
    open_recursion_check(dns_ip)
if __name__ == "__main__":
    main()
