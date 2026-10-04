<?php
/*
 * int-pfsense-v2.php
 * ---------------------------------------------------------------------------
 * This script just asks the user for what NIC should be assigned to each
 * internal network (as well as the WAN).
 *
 *   WAN  (attack-net uplink) -> static 172.16.10.2/24, gateway 172.16.10.1
 *   LAN  (int-net-1)         -> 192.168.10.1/24
 *   OPT1 (int-net-2, admin)  -> 10.1.1.1/24
 *   OPT2 (int-net-3)         -> 172.16.0.1/24
 *
 * No block rules (transparent router); permissive allow-all per interface.
 * No admin-password change. DHCP server OFF on every interface. Idempotent.
 *
 * -d or --debug enables verbose process + results output
 * -l or --logging enables logging on the per-interface allow rules
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
$PLAN = array(
    "wan"  => array("WAN (attack-net uplink, 172.16.10.2/24)", "172.16.10.2",  "24"),
    "lan"  => array("int-net-1 (192.168.10.1/24)",             "192.168.10.1", "24"),
    "opt1" => array("int-net-2 / ADMIN (10.1.1.1/24)",         "10.1.1.1",     "24"),
    "opt2" => array("int-net-3 (172.16.0.1/24)",               "172.16.0.1",   "24"),
);

// Helper functions
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

// prompts for interface to choose
function _choose_iface($label, &$pool) {
    $keys = array_keys($pool);
    for ($try = 0; $try < 5; $try++) {
        fwrite(STDOUT, "\nChoose the interface for $label:\n");
        for ($i = 0; $i < count($keys); $i++) {
            fwrite(STDOUT, "  " . ($i + 1) . ") " . $keys[$i] .
                           "   MAC " . $pool[$keys[$i]] . "\n");
        }
        fwrite(STDOUT, "Enter 1-" . count($keys) . ": ");
        $choice = trim((string) fgets(STDIN));
        $n = (int) $choice;
        if ($choice !== "" && (string) $n === $choice && $n >= 1 && $n <= count($keys)) {
            $picked = $keys[$n - 1];
            unset($pool[$picked]);
            return $picked;
        }
        fwrite(STDOUT, "  '$choice' is not a valid choice.\n");
    }
    fwrite(STDERR, "!! Too many invalid entries. NOTHING WRITTEN. (Run interactively.)\n");
    exit(1);
}

// get NICs in an array
$nics = _nic_list();
if (count($nics) < 4) {
    fwrite(STDERR, "!! Need 4 NICs, found " . count($nics) . " (" .
                   implode(", ", $nics) . "). NOTHING WRITTEN.\n");
    exit(1);
}
$pool = array();
foreach ($nics as $if) $pool[$if] = _nic_mac($if);

echo "[*] Interfaces on this box:\n";
foreach ($pool as $if => $mac) echo "      $if   MAC $mac\n";
echo "    Map these MACs against the vSphere adapter list, then choose below.\n";

// prompt the user for each NIC
$assigned = array();
foreach ($PLAN as $slot => $p) {
    $assigned[$slot] = _choose_iface($p[0], $pool);
    dbg("$slot <- {$assigned[$slot]}");
}

echo "\n[*] Selections:\n";
foreach ($PLAN as $slot => $p) {
    echo "      " . str_pad($slot, 4) . " ({$p[1]}/{$p[2]}): {$assigned[$slot]}\n";
}
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
    list(, $ip, $prefix) = $p;
    if (!is_array($config['interfaces'][$slot])) $config['interfaces'][$slot] = array();
    $config['interfaces'][$slot]['enable'] = "";
    $config['interfaces'][$slot]['if']     = $assigned[$slot];
    $config['interfaces'][$slot]['ipaddr'] = $ip;
    $config['interfaces'][$slot]['subnet'] = (string) $prefix;
    if (empty($config['interfaces'][$slot]['descr'])) {
        $config['interfaces'][$slot]['descr'] = strtoupper($slot);
    }
    if (is_array($config['dhcpd'] ?? null) && is_array($config['dhcpd'][$slot] ?? null)) {
        unset($config['dhcpd'][$slot]['enable']);
    }
    dbg("$slot -> if={$assigned[$slot]} ip=$ip/$prefix");
}

// allow private-sourced traffic through WAN
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
write_config("int-pfsense (manual): 4 interfaces assigned, default gw {$WAN_GW_IP}, allow-all per interface");

foreach (array_keys($PLAN) as $slot) interface_configure($slot, true);
services_dhcpd_configure();
filter_configure();
dbg("interfaces + dhcpd + filter reloaded");

echo "\nDone.\n";
foreach ($PLAN as $slot => $p) {
    echo "  " . str_pad($slot, 4) . " ({$assigned[$slot]}): {$p[1]}/{$p[2]}\n";
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