<?php
/*
 * ext-pfsense.php
 * ---------------------------------------------------------------------------
 * Sets the internal and external interfaces to their proper values. External
 * will be assigned a dhcp IP from RLES, while the internal network will be
 * 172.16.10.0/24 with the internal interface having the 172.16.10.1 address.
 *
 * Adds a firewall rule that drops traffic going from the internal network
 * to external IP when the IP is a private IP or a carrier grade IP. This
 * configuration is necessary in order to prevent the AI from attacking other
 * potentially vulnerable machines on RLES.
 *
 * Replaces the admin password with the pre-generated bcrypt hash in $ADMIN_PW.
 * The passwords will be stored elsewhere until testing is completed, at which
 * time they'll be added to the README.md or a wiki.
 *
 * Idempotent, this will not ruin anything if run multiple times
 * ---------------------------------------------------------------------------
 */

require_once("config.inc");
require_once("auth.inc");
require_once("interfaces.inc");
require_once("services.inc");
require_once("filter.inc");
require_once("util.inc");
require_once("functions.inc");

// Generate passwords with bcrypt using:
//   php -r 'echo password_hash("NewPassw0rd", PASSWORD_BCRYPT), "\n";'
// TODO: determine if bcrypt is being used or not
$ADMIN_PW = '$2y$12$hNWDGor.IzhvV7FD2KR4Req4pGKuRf.ffqsAIyfjLrLylbqGilQQm';

global $config;

// This might be helpful for future:
//   php -r 'require("config.inc"); print_r(get_configured_interface_with_descr());'
$WAN = "wan";
$LAN = "lan";

// TODO: FIX THESE, they're the interface names
$WAN_IF = "";
$LAN_IF = "";

// LAN IP and subnet range
$LAN_IP     = "172.16.10.1";
$LAN_SUBNET = "24";

// Alias and rule variables
$ALIAS_NAME = "PRIVATE_CGNAT_DESTS";
$RANGES     = "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10";
$ALIAS_DESCR = "Private + CGNAT destinations";
$RULE_DESCR  = "Block internal attack-net -> external private/CGNAT (contain the pentesting AI)";

// This will determine whether the script is running in debug mode or not
$DEBUG = in_array("-d", $argv, true) || in_array("--debug", $argv, true);

// WAN config
if (!is_array($config['interfaces'][$WAN])) $config['interfaces'][$WAN] = array();
$config['interfaces'][$WAN]['enable'] = "";
$config['interfaces'][$WAN]['ipaddr'] = "dhcp";
if ($WAN_IF !== "") $config['interfaces'][$WAN]['if'] = $WAN_IF;
if (empty($config['interfaces'][$WAN]['descr'])) $config['interfaces'][$WAN]['descr'] = "WAN";

// LAN config
if (!is_array($config['interfaces'][$LAN])) $config['interfaces'][$LAN] = array();
$config['interfaces'][$LAN]['enable'] = "";
$config['interfaces'][$LAN]['ipaddr'] = $LAN_IP;
$config['interfaces'][$LAN]['subnet'] = (string) $LAN_SUBNET;
if ($LAN_IF !== "") $config['interfaces'][$LAN]['if'] = $LAN_IF;
if (empty($config['interfaces'][$LAN]['descr'])) $config['interfaces'][$LAN]['descr'] = "ATTACKNET";

// shut off DHCP
if (is_array($config['dhcpd']) && is_array($config['dhcpd'][$LAN])) {
    unset($config['dhcpd'][$LAN]['enable']);
}

// Alias config
if (!is_array($config['aliases']))          $config['aliases'] = array();
if (!is_array($config['aliases']['alias'] ?? null)) $config['aliases']['alias'] = array();

// Create/update the firewall alias
$found = false;
foreach ($config['aliases']['alias'] as &$a) {
    if (($a['name'] ?? '') === $ALIAS_NAME) {
        $a['type'] = "network"; $a['address'] = $RANGES; $a['descr'] = $ALIAS_DESCR;
        $found = true; break;
    }
}
unset($a);
if (!$found) {
    $config['aliases']['alias'][] = array(
        'name' => $ALIAS_NAME, 'type' => "network",
        'address' => $RANGES, 'descr' => $ALIAS_DESCR,
    );
}

// Firewall block rule
if (!is_array($config['filter']))         $config['filter'] = array();
if (!is_array($config['filter']['rule'] ?? null)) $config['filter']['rule'] = array();

// Keep the existing rule's tracker so log entries still map to it across reruns
$tracker = (string) time();
foreach ($config['filter']['rule'] as $r) {
    if (($r['descr'] ?? '') === $RULE_DESCR && !empty($r['tracker'])) {
        $tracker = $r['tracker']; break;
    }
}

// remove the old rule if it exists
$config['filter']['rule'] = array_values(array_filter(
    $config['filter']['rule'],
    function ($r) use ($RULE_DESCR) { return ($r['descr'] ?? '') !== $RULE_DESCR; }
));

// builds the firewall rule
$rule = array(
    'type'        => "block",
    'interface'   => $LAN,
    'ipprotocol'  => "inet",                      // IPv4 only
    'source'      => array('network' => $LAN),
    'destination' => array('address' => $ALIAS_NAME),
    'descr'       => $RULE_DESCR,
    'tracker'     => $tracker,
);

# enable debug logging if debugging enabled
if ($DEBUG) $rule['log'] = "";

// Put this at the front of the rules
array_unshift($config['filter']['rule'], $rule);

// check to see if admin password is valid
if (!preg_match('/^\$2y\$\d{2}\$[.\/A-Za-z0-9]{53}$/', $ADMIN_PW)) {
    fwrite(STDERR, "ADMIN_PW is not a bcrypt hash (\$2y\$...), aborting before writing config.\n");
    exit(1);
}

// set the admin password hash manually
$admin = null;
foreach ($config['system']['user'] as &$u) {
    if ((string) ($u['uid'] ?? '') === "0") {
        // Drop any other stored hash so the old password can't still match
        unset($u['password'], $u['md5-hash'], $u['sha512-hash']);
        $u['bcrypt-hash'] = $ADMIN_PW;
        $admin = $u; break;
    }
}
unset($u);
if ($admin === null) {
    fwrite(STDERR, "admin (uid 0) not found in config, aborting.\n");
    exit(1);
}

// Commit & apply changes
write_config("lab setup: wan dhcp, lan static {$LAN_IP}/{$LAN_SUBNET} (no dhcpd), containment rule, admin password");

local_user_set($admin);         // syncs the hash to /etc/master.passwd (console/SSH root too)

interface_configure($WAN, true);
interface_configure($LAN, true);
services_dhcpd_configure();     // realizes the DHCP-server-off state
filter_configure();

echo "Done.\n";
echo "  WAN  ({$WAN}): DHCP client\n";
echo "  LAN  ({$LAN}): {$LAN_IP}/{$LAN_SUBNET}, DHCP server disabled\n";
echo "  Rule: block {$LAN} net -> {$ALIAS_NAME}\n";
echo "  Admin: password hash replaced\n";
echo "Verify: Firewall > Rules (attack-net), Status > Interfaces, Status > System Logs > Firewall.\n";