<?php
/*
 * int-pfsense.php
 * ---------------------------------------------------------------------------
 * Configures the internal router
 *
 *   WAN  (attack-net uplink) -> static 172.16.10.2/24, gateway 172.16.10.1
 *   LAN  (int-net-1)         -> 192.168.10.1/24
 *   OPT1 (int-net-2, admin)  -> 10.1.1.1/24
 *   OPT2 (int-net-3)         -> 172.16.0.1/24
 *
 * Interface detection:
 *   WAN      -> ARP-probe the attack-net hosts (ext-pfsense/attacker/langfuse).
 *   int-net-1 -> only 1 internal network with 2 hosts
 *   int-net-2/3 -> it asks the user for which network is the host based on MAC
 *
 * -d or--debug enables verbose process + results output
 * -l or--logging flag enables logging on the per-interface allow rules (high volume)
 * ---------------------------------------------------------------------------
 */

require_once("config.inc");
require_once("interfaces.inc");
require_once("services.inc");
require_once("filter.inc");
require_once("util.inc");
require_once("functions.inc");

global $config;

$DEBUG   = in_array("-d", $argv, true) || in_array("--debug", $argv, true);
$LOGGING = in_array("-l", $argv, true) || in_array("--logging", $argv, true);

function dbg($msg) { global $DEBUG; if ($DEBUG) fwrite(STDOUT, "[debug] $msg\n"); }

$WAN_GW_IP   = "172.16.10.1";
$WAN_GW_NAME = "GW_ATTACKNET";

// Known hosts used to fingerprint segments.
$ATTACK_TARGETS = array("172.16.10.1", "172.16.10.10", "172.16.10.11");
$ATTACK_PROBE   = "172.16.10.252";
$NET1_HOSTS     = array("192.168.10.10", "192.168.10.11");   // ad-serv, elem-serv
$NET1_PROBE     = "192.168.10.250";

// slot => [descr, interface IP, subnet]
$PLAN = array(
    "wan"  => array("ATTACKNET_UPLINK", "172.16.10.2",  "24"),
    "lan"  => array("INT_NET_1",        "192.168.10.1", "24"),
    "opt1" => array("INT_NET_2_ADMIN",  "10.1.1.1",     "24"),
    "opt2" => array("INT_NET_3",        "172.16.0.1",   "24"),
);

// Non-interactive override: the NIC that is the admin network (int-net-2).
$ADMIN_NET_IF = getenv("ADMIN_NET_IF") ?: "";

// helper functions
function _nic_list() {
    $out = trim((string) shell_exec("ifconfig -l 2>/dev/null"));
    return array_values(array_filter(preg_split('/\s+/', $out), function ($i) {
        return preg_match('/^(vmx|vtnet|em|igb|ix|re|bge)\d+$/', $i);
    }));
}
function _nic_mac($if) {
    $out = (string) shell_exec("ifconfig " . escapeshellarg($if) . " 2>/dev/null");
    if (preg_match('/(?:ether|lladdr)\s+([0-9a-fA-F:]{17})/', $out, $m)) return $m[1];
    return "??:??:??:??:??:??";
}
// Count how many of $targets answer ARP on $if.
function _count_responders($if, $src, $prefix, $targets) {
    exec("ifconfig " . escapeshellarg($if) . " up 2>/dev/null");
    exec("ifconfig " . escapeshellarg($if) . " inet " .
         escapeshellarg("$src/$prefix") . " alias 2>/dev/null");
    $count = 0;
    foreach ($targets as $t) {
        exec("arp -d " . escapeshellarg($t) . " 2>/dev/null");
        exec("ping -c1 -W1000 -S " . escapeshellarg($src) . " " .
             escapeshellarg($t) . " >/dev/null 2>&1");
        $arp = (string) shell_exec("arp -n " . escapeshellarg($t) . " 2>/dev/null");
        if (preg_match('/([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}/', $arp)) $count++;
    }
    exec("ifconfig " . escapeshellarg($if) . " inet " .
         escapeshellarg($src) . " -alias 2>/dev/null");
    return $count;
}

// Get WAN
echo "[*] Detecting int-pfsense interfaces\n";
$nics = _nic_list();
dbg("NICs found: " . implode(", ", $nics));

$wan_if = "";
foreach ($nics as $if) {
    $c = _count_responders($if, $ATTACK_PROBE, "24", $ATTACK_TARGETS);
    dbg("wan probe: $if -> $c attack-net responder(s)");
    if ($c > 0) { $wan_if = $if; break; }
}
if ($wan_if === "") {
    fwrite(STDERR, "!! WAN (attack-net) not found. Is the uplink to ext-pfsense live? NOTHING WRITTEN.\n");
    exit(1);
}
echo "    wan  (attack-net)      : $wan_if\n";

$internal = array_values(array_diff($nics, array($wan_if)));
if (count($internal) < 3) {
    fwrite(STDERR, "!! Expected 3 internal NICs, found " . count($internal) . ". NOTHING WRITTEN.\n");
    exit(1);
}

// Determine int-net-1 based on number of machines
$net1_if = "";
foreach ($internal as $if) {
    $c = _count_responders($if, $NET1_PROBE, "24", $NET1_HOSTS);
    dbg("net1 probe: $if -> $c of " . count($NET1_HOSTS) . " int-net-1 hosts");
    if ($c > 1) { $net1_if = $if; break; }
}
if ($net1_if === "") {
    fwrite(STDERR, "!! int-net-1 not found (need >1 responder). NOTHING WRITTEN.\n");
    fwrite(STDERR, "   Both ad-serv (192.168.10.10) and elem-serv (192.168.10.11) must be up.\n");
    exit(1);
}
echo "    lan  (int-net-1)       : $net1_if  (2+ hosts)\n";

// put together the remaining NICs
$remaining = array_values(array_diff($internal, array($net1_if)));   // exactly 2

if ($ADMIN_NET_IF !== "") {
    if (!in_array($ADMIN_NET_IF, $remaining, true)) {
        fwrite(STDERR, "!! ADMIN_NET_IF=$ADMIN_NET_IF is not one of the remaining NICs (" .
                       implode(", ", $remaining) . "). NOTHING WRITTEN.\n");
        exit(1);
    }
    $admin_if = $ADMIN_NET_IF;
    echo "    admin network (override): $admin_if\n";
} else {
    $admin_if = "";
    // ask the user for the admin NIC based on the MAC address of the unassigned NICs (Based on LAN101/2/3)
    for ($try = 0; $try < 3 && $admin_if === ""; $try++) {
        fwrite(STDOUT, "\nWhich interface is the ADMIN network (int-net-2, 10.1.1.0/24)?\n");
        fwrite(STDOUT, "  1) {$remaining[0]}   MAC " . _nic_mac($remaining[0]) . "\n");
        fwrite(STDOUT, "  2) {$remaining[1]}   MAC " . _nic_mac($remaining[1]) . "\n");
        fwrite(STDOUT, "Enter 1 or 2: ");
        $choice = trim((string) fgets(STDIN));
        if ($choice === "1")      $admin_if = $remaining[0];
        elseif ($choice === "2")  $admin_if = $remaining[1];
        else fwrite(STDOUT, "  '$choice' is not 1 or 2.\n");
    }
    if ($admin_if === "") {
        fwrite(STDERR, "!! No valid selection. NOTHING WRITTEN. (Run interactively, or set ADMIN_NET_IF.)\n");
        exit(1);
    }
}
$net3_if = ($admin_if === $remaining[0]) ? $remaining[1] : $remaining[0];

echo "    opt1 (int-net-2 admin) : $admin_if\n";
echo "    opt2 (int-net-3)       : $net3_if\n";

$assigned = array("wan" => $wan_if, "lan" => $net1_if, "opt1" => $admin_if, "opt2" => $net3_if);

// Free opt slots currently bound to a chosen NIC
foreach (array_keys($config['interfaces'] ?? array()) as $lif) {
    if (array_key_exists($lif, $PLAN)) continue;
    $boundIf = $config['interfaces'][$lif]['if'] ?? '';
    if ($boundIf !== '' && in_array($boundIf, $assigned, true)) {
        unset($config['interfaces'][$lif]);
        dbg("freed slot $lif (was bound to $boundIf)");
    }
}

// Apply interface config
foreach ($PLAN as $slot => $p) {
    list($descr, $ip, $prefix) = $p;
    if (!is_array($config['interfaces'][$slot])) $config['interfaces'][$slot] = array();
    $config['interfaces'][$slot]['enable'] = "";
    $config['interfaces'][$slot]['if']     = $assigned[$slot];
    $config['interfaces'][$slot]['ipaddr'] = $ip;
    $config['interfaces'][$slot]['subnet'] = (string) $prefix;
    $config['interfaces'][$slot]['descr']  = $descr;
    if (is_array($config['dhcpd'] ?? null) && is_array($config['dhcpd'][$slot] ?? null)) {
        unset($config['dhcpd'][$slot]['enable']);
    }
    dbg("$slot -> if={$assigned[$slot]} ip=$ip/$prefix descr=$descr");
}

// WAN is a routed uplink, not an edge: allow private-sourced traffic through.
unset($config['interfaces']['wan']['blockpriv'], $config['interfaces']['wan']['blockbogons']);
dbg("wan: blockpriv/blockbogons cleared (routed uplink)");

// Default gateway via ext-pfsense
if (!is_array($config['gateways'] ?? null)) $config['gateways'] = array();
if (!is_array($config['gateways']['gateway_item'] ?? null)) $config['gateways']['gateway_item'] = array();
$gwfound = false;
foreach ($config['gateways']['gateway_item'] as &$g) {
    if (($g['name'] ?? '') === $WAN_GW_NAME) {
        $g['interface'] = "wan"; $g['gateway'] = $WAN_GW_IP; $g['ipprotocol'] = "inet";
        $gwfound = true; break;
    }
}
unset($g);
if (!$gwfound) {
    $config['gateways']['gateway_item'][] = array(
        'interface' => "wan", 'gateway' => $WAN_GW_IP, 'name' => $WAN_GW_NAME,
        'weight' => "1", 'ipprotocol' => "inet", 'descr' => "Uplink to ext-pfsense",
    );
}
$config['interfaces']['wan']['gateway'] = $WAN_GW_NAME;
$config['gateways']['defaultgw4'] = $WAN_GW_NAME;
dbg("gateway $WAN_GW_NAME -> $WAN_GW_IP set as default");

// Permissive allow-all rule per interface (transparent router)
if (!is_array($config['filter'] ?? null)) $config['filter'] = array();
if (!is_array($config['filter']['rule'] ?? null)) $config['filter']['rule'] = array();

foreach (array_keys($PLAN) as $slot) {
    $rdescr = "Allow all on {$slot} (int-pfsense transparent router)";
    $tracker = (string) time();
    foreach ($config['filter']['rule'] as $r) {
        if (($r['descr'] ?? '') === $rdescr && !empty($r['tracker'])) { $tracker = $r['tracker']; break; }
    }
    $config['filter']['rule'] = array_values(array_filter(
        $config['filter']['rule'],
        function ($r) use ($rdescr) { return ($r['descr'] ?? '') !== $rdescr; }
    ));
    $rule = array(
        'type' => "pass", 'interface' => $slot, 'ipprotocol' => "inet",
        'source' => array('any' => ''), 'destination' => array('any' => ''),
        'descr' => $rdescr, 'tracker' => $tracker,
    );
    if ($LOGGING) $rule['log'] = "";
    $config['filter']['rule'][] = $rule;
    dbg("allow-all rule on $slot (logging=" . ($LOGGING ? "on" : "off") . ")");
}

// Commit & apply
dbg("committing config (write_config)...");
write_config("int-pfsense: 4 interfaces assigned, default gw {$WAN_GW_IP}, allow-all per interface");

foreach (array_keys($PLAN) as $slot) interface_configure($slot, true);
services_dhcpd_configure();
filter_configure();
dbg("interfaces + dhcpd + filter reloaded");

echo "Done.\n";
foreach ($PLAN as $slot => $p) {
    echo "  " . str_pad($slot, 4) . " ({$assigned[$slot]}): {$p[1]}/{$p[2]}  [{$p[0]}]\n";
}
echo "  default gw: {$WAN_GW_IP} (ext-pfsense)\n";
echo "  No block rules (transparent router); allow-all per interface" .
     ($LOGGING ? " with logging" : "") . ".\n";

if ($DEBUG) {
    echo "\n[debug] results summary\n";
    foreach ($PLAN as $slot => $p) {
        echo "[debug]   $slot: if=" . ($config['interfaces'][$slot]['if'] ?? '?') .
             " ip=" . ($config['interfaces'][$slot]['ipaddr'] ?? '?') .
             "/" . ($config['interfaces'][$slot]['subnet'] ?? '?') . "\n";
    }
}

echo "Verify: Interfaces > Assignments, Status > Gateways, Firewall > Rules.\n";