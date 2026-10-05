# infrastructure-scripts

## WORK IN PROGRESS

The repo as of now is a work in progress and will not work. Automation scripts are being created and tested over time, but they should be ready by October 5

## Layout

### Network Layout and Chart:

![Network Layout](docs/diagrams/networklayout.svg)

![Network Chart](docs/diagrams/netchart.svg)

### Users

![AD Users](docs/diagrams/users.svg)

### VMs and Provisioning

! TODO: ADD THIS ONCE CONFIRMING HOW MANY RESOURCES ARE ALLOCATED TO THE FIREWALLS
(RLES is down at the moment)

## Usage

The setup needs to be run in a specific way, which is annoying but very necessary. Follow the directions given in this section in order to make sure there are no issues.

### Configure the External pfSense Router

<details>
<summary>STEPS</summary>

1) Go to the RLES settings for the `ext-pfsense` VM and check the "Network" tab:

![ext-pfsense NICs](docs/images/ext-networks-rles.png)

* Note the `NAT-network`'s MAC address (which will be your WAN address)
* Note the `Attacker_LAN`'s MAC address (which will be your LAN address)

2) Open the console for your `ext-pfsense` VM:

* select the right interfaces for WAN and LAN (needed in order to download config scripts)
* choose option "1) Assign Interfaces"
* Answer "n" or "no" to setting up VLANs
* choose the corrrect options for LAN and WAN based on the MAC addresses displayed earlier and the interface MAC addresses shown in pfsense (they need to match)
* when it asks you to enter the optional interface, just hit enter
* enter "y" to proceed
* (**IMPORTANT**) REASSIGN THE INTERFACES USING THE NAT NIC AS THE WAN AND THE ATTACKER NIC AS THE LAN
  * I've spent hours trying to get this to consistently assign the right IP addresses and it just won't do it

3) Open the consoles for your `attacker` and `langfuse` VMs:

* Assign them the following:
  * IP address
    * attacker: "172.16.10.10"
    * langfuse: "172.16.10.11"
  * Netmask: "255.255.255.0"
  * Gateway: "172.16.10.1"
  * DNS Servers: "8.8.8.8,1.1.1.1"
<small>Without setting this up, the firewall will not recognize the correct interface and won't know which one to set as the attacker network</small>

4) Go back to the `ext-pfsense` VM and select option "8) Shell" and enter the following commands:

```bash
curl -O https://raw.githubusercontent.com/Post-Exploitation-LLM-Behavior/infrastructure-scripts/refs/heads/main/firewalls/ext-pfsense.php
chmod 755 ext-pfsense.php
php ext-pfsense.php --logging --debug # the logging logs all attempts that are made to reach IP addresses the AI should not be reaching out to
```

5) Test connection on the `attacker` and `langfuse` VMs by pinging google.com and updating with apt

</details>

### Configure the Internal pfSense Router

<details>
<summary>STEPS</summary>

1) Open 

</details>