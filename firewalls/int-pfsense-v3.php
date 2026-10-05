<?php
/*
 * int-pfsense.php — interactive interface assignment for the internal router.
 *   wan  (attack-net)  172.16.10.2/24  gw 172.16.10.1
 *   lan  (int-net-1)   192.168.10.1/24
 *   opt1 (int-net-2)   10.1.1.1/24
 *   opt2 (int-net-3)   172.16.0.1/24
 * Flags: -d/--debug  -l/--logging  -y/--yes (skip confirm)
 * Optional env overrides (skip the prompt for that slot): WAN_IF NET1_IF ADMIN_NET_IF NET3_IF
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
$ASSUME  = in_array("-y", $argv, true) || in_array("--yes", $argv, true);

function dbg($m) { global $DEBUG; if ($DEBUG) fwrite(STDOUT, "[debug] $m\n"); }

$WAN_GW_IP   = "172.16.10.1";
$WAN_GW_NAME = "GW_ATTACKNET";

// dictionary of networks
$PLAN = array(
    "wan"  => array("ATTACKNET_UPLINK", "172.16.10.2",  "24", "WAN_IF"),
    "lan"  => array("INT_NET_1",        "192.168.10.1", "24", "NET1_IF"),
    "opt1" => array("INT_NET_2_ADMIN",  "10.1.1.1",     "24", "ADMIN_NET_IF"),
    "opt2" => array("INT_NET_3",        "172.16.0.1",   "24", "NET3_IF"),
);

// Hosts used only for the post-config reachability check. Add known IPs per net.
$ATTACK_TEST_HOSTS = array("172.16.10.1", "172.16.10.10", "172.16.10.11");
$INT_TEST_HOSTS = array(
    "lan"  => array("192.168.10.10", "192.168.10.11"),
    "opt1" => array(),   // int-net-2 (admin) hosts
    "opt2" => array(),   // int-net-3 hosts
);

// helpers
function _nic_list() {
    $out = trim((string) shell_exec("ifconfig -l 2>/dev/null"));
    return array_values(array_filter(preg_split('/\s+/', $out), function ($i) {
        return preg_match('/^(vmx|vtnet|em|igb|ix|re|bge)\d+$/', $i);
    }));
}
function _nic_mac($if) {
    $out = (string) shell_exec("ifconfig " . escapeshellarg($if) . " 2>/dev/null");
    return preg_match('/(?:ether|lladdr)\s+([0-9a-fA-F:]{17})/', $out, $m) ? $m[1] : "??:??:??:??:??:??";
}
function _nic_status($if) {
    $out = (string) shell_exec("ifconfig " . escapeshellarg($if) . " 2>/dev/null");
    return preg_match('/status:\s*(\S+)/', $out, $m) ? $m[1] : "?";
}
function _if_has_ip($if, $ip) {
    $out = (string) shell_exec("ifconfig " . escapeshellarg($if) . " inet 2>/dev/null");
    return (bool) preg_match('/inet\s+' . preg_quote($ip, '/') . '\b/', $out);
}
function _default_gw() {
    $out = (string) shell_exec("netstat -rn -f inet 2>/dev/null");
    return preg_match('/^default\s+(\S+)/m', $out, $m) ? $m[1] : "";
}
function _ping($dst, $src = "") {
    $cmd = "ping -c2 -W1000 " . ($src !== "" ? "-S " . escapeshellarg($src) . " " : "") .
           escapeshellarg($dst) . " >/dev/null 2>&1";
    exec($cmd, $o, $rc);
    return $rc === 0;
}
function _pass($b) { return $b ? "PASS" : "FAIL"; }

// interactive assignment
$all = _nic_list();
echo "[*] Detected interfaces:\n";
foreach ($all as $if) printf("    %-6s MAC %s  [%s]\n", $if, _nic_mac($if), _nic_status($if));
if (count($all) < 4) {
    fwrite(STDERR, "!! Need 4 NICs, found " . count($all) . ". NOTHING WRITTEN.\n");
    exit(1);
}

function assign_role($slot, $label, $netdesc, $envvar, &$pool) {
    $env = getenv($envvar) ?: "";
    if ($env !== "") {
        if (in_array($env, $pool, true)) {
            $pool = array_values(array_diff($pool, array($env)));
            echo "    $slot <- $env (via $envvar)\n";
            return $env;
        }
        fwrite(STDERR, "!! $envvar=$env is not an available NIC; prompting instead.\n");
    }
    while (true) {
        echo "\n$label  ($netdesc)\n";
        foreach ($pool as $i => $if)
            printf("  %d) %-6s MAC %s  [%s]\n", $i + 1, $if, _nic_mac($if), _nic_status($if));
        echo "Select 1-" . count($pool) . ": ";
        $c = trim((string) fgets(STDIN));
        if (ctype_digit($c)) {
            $x = (int) $c - 1;
            if ($x >= 0 && $x < count($pool)) {
                $sel = $pool[$x];
                $pool = array_values(array_diff($pool, array($sel)));
                return $sel;
            }
        }
        echo "  '$c' is not a valid choice.\n";
    }
}

$pool = $all;
$assigned = array();
$assigned['wan']  = assign_role('wan',  "WAN",  "attack-net uplink, 172.16.10.2/24",  "WAN_IF",       $pool);
$assigned['lan']  = assign_role('lan',  "LAN",  "int-net-1, 192.168.10.1/24",         "NET1_IF",      $pool);
$assigned['opt1'] = assign_role('opt1', "OPT1", "int-net-2 admin, 10.1.1.1/24",       "ADMIN_NET_IF", $pool);
$assigned['opt2'] = assign_role('opt2', "OPT2", "int-net-3, 172.16.0.1/24",           "NET3_IF",      $pool);

echo "\nPlanned assignment:\n";
foreach ($PLAN as $slot => $p)
    printf("  %-4s -> %-6s %s/%s  [%s]  MAC %s\n",
        $slot, $assigned[$slot], $p[1], $p[2], $p[0], _nic_mac($assigned[$slot]));
if (!$ASSUME) {
    echo "Proceed and write config? [y/N]: ";
    $a = strtolower(trim((string) fgets(STDIN)));
    if ($a !== "y" && $a !== "yes") { echo "Aborted. NOTHING WRITTEN.\n"; exit(0); }
}

// free opt slots currently bound to a chosen NIC
foreach (array_keys($config['interfaces'] ?? array()) as $lif) {
    if (array_key_exists($lif, $PLAN)) continue;
    $b = $config['interfaces'][$lif]['if'] ?? '';
    if ($b !== '' && in_array($b, $assigned, true)) { unset($config['interfaces'][$lif]); dbg("freed slot $lif (was $b)"); }
}

// apply interfaces
foreach ($PLAN as $slot => $p) {
    list($descr, $ip, $prefix) = $p;
    if (!is_array($config['interfaces'][$slot] ?? null)) $config['interfaces'][$slot] = array();
    $config['interfaces'][$slot]['enable'] = "";
    $config['interfaces'][$slot]['if']     = $assigned[$slot];
    $config['interfaces'][$slot]['ipaddr'] = $ip;
    $config['interfaces'][$slot]['subnet'] = (string) $prefix;
    $config['interfaces'][$slot]['descr']  = $descr;
    if (is_array($config['dhcpd'][$slot] ?? null)) unset($config['dhcpd'][$slot]['enable']);
}
unset($config['interfaces']['wan']['blockpriv'], $config['interfaces']['wan']['blockbogons']);

// default gateway via ext-pfsense
if (!is_array($config['gateways'] ?? null)) $config['gateways'] = array();
if (!is_array($config['gateways']['gateway_item'] ?? null)) $config['gateways']['gateway_item'] = array();
$gwfound = false;
foreach ($config['gateways']['gateway_item'] as &$g) {
    if (($g['name'] ?? '') === $WAN_GW_NAME) {
        $g['interface'] = "wan"; $g['gateway'] = $WAN_GW_IP; $g['ipprotocol'] = "inet"; $gwfound = true; break;
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

// allow-all per interface (transit router); disable reply-to on wan so transit isn't forced back at the gw
if (!is_array($config['filter'] ?? null)) $config['filter'] = array();
if (!is_array($config['filter']['rule'] ?? null)) $config['filter']['rule'] = array();
foreach (array_keys($PLAN) as $slot) {
    $rdescr = "Allow all on $slot (int-pfsense transit router)";
    $tracker = (string) time();
    foreach ($config['filter']['rule'] as $r)
        if (($r['descr'] ?? '') === $rdescr && !empty($r['tracker'])) { $tracker = $r['tracker']; break; }
    $config['filter']['rule'] = array_values(array_filter($config['filter']['rule'],
        function ($r) use ($rdescr) { return ($r['descr'] ?? '') !== $rdescr; }));
    $rule = array(
        'type' => "pass", 'interface' => $slot, 'ipprotocol' => "inet",
        'source' => array('any' => ''), 'destination' => array('any' => ''),
        'descr' => $rdescr, 'tracker' => $tracker,
    );
    if ($slot === "wan") $rule['disablereplyto'] = "";
    if ($LOGGING) $rule['log'] = "";
    $config['filter']['rule'][] = $rule;
}

// commit & apply
write_config("int-pfsense: interactive assignment, default gw $WAN_GW_IP, allow-all per interface");
foreach (array_keys($PLAN) as $slot) interface_configure($slot, true);
services_dhcpd_configure();
filter_configure();

// verify the config actually took
echo "\n[*] Verifying configuration\n";
$persist = function_exists('parse_config') ? parse_config(true) : $config;
$allok = true;
foreach ($PLAN as $slot => $p) {
    $want = $assigned[$slot]; $ip = $p[1];
    $cif = $persist['interfaces'][$slot]['if'] ?? '';
    $cok = ($cif === $want);
    $live = _if_has_ip($want, $ip);
    if (!$cok || !$live) $allok = false;
    printf("    %-4s: config if=%-6s %s | live %s/%s %s\n", $slot, $cif ?: "(none)", _pass($cok), $ip, $p[2], _pass($live));
}
$gw = _default_gw(); $gwok = ($gw === $WAN_GW_IP);
printf("    gateway: default -> %s %s\n", $gw ?: "(none)", _pass($gwok));
$wan_nic = $assigned['wan'];
$pf = (string) shell_exec("pfctl -sr 2>/dev/null");
$wanpass = (bool) preg_match('/pass\s+in\b.*\bon\s+' . preg_quote($wan_nic, '/') . '\b/', $pf);
printf("    firewall: pass-in on wan(%s) %s\n", $wan_nic, _pass($wanpass));
if (!$allok || !$gwok || !$wanpass)
    echo "    !! one or more checks FAILED — inspect Interfaces/Gateways/Rules before continuing.\n";

// verify attack-net <-> int-net reachability (run from int-pfsense)
echo "\n[*] Reachability check\n";
$WAN_IP = $PLAN['wan'][1];
$gw_reachable = false;
echo "  attack-net (pinged from $WAN_IP):\n";
foreach ($ATTACK_TEST_HOSTS as $h) {
    $r = _ping($h, $WAN_IP);
    if ($h === $WAN_GW_IP) $gw_reachable = $r;
    printf("    %-15s %s\n", $h, $r ? "up" : "unreachable");
}
if (!$gw_reachable)
    echo "    !! $WAN_GW_IP (ext-pfsense) unreachable — WAN NIC choice or uplink is likely wrong.\n";

echo "  int-nets  (host= up on its subnet?, transit= attack-net src can reach it?):\n";
foreach (array("lan", "opt1", "opt2") as $slot) {
    $hosts = $INT_TEST_HOSTS[$slot] ?? array();
    if (!$hosts) { printf("    %-4s: no test hosts configured\n", $slot); continue; }
    $iip = $PLAN[$slot][1];
    foreach ($hosts as $h) {
        $up = _ping($h, $iip);          // sourced from the int interface
        $tr = _ping($h, $WAN_IP);        // sourced from the attack-net-facing IP
        $verdict = ($up && $tr) ? "attack-net OK"
                 : ($up ? "host up, return route to attack-net BROKEN"
                        : "host down / interface misassigned");
        printf("    %-4s %-15s host=%s transit=%s -> %s\n", $slot, $h, $up ? "ok" : "x", $tr ? "ok" : "x", $verdict);
    }
}

// summary
echo "\nDone.\n";
foreach ($PLAN as $slot => $p) echo "  " . str_pad($slot, 4) . " (" . $assigned[$slot] . "): " . $p[1] . "/" . $p[2] . "  [" . $p[0] . "]\n";
echo "  default gw: $WAN_GW_IP (ext-pfsense)\n";
echo "  allow-all per interface" . ($LOGGING ? " + logging" : "") . ", reply-to disabled on wan.\n";
echo "  NOTE: for attacker-net hosts to actually route into the int-nets, ext-pfsense needs\n";
echo "        static routes for 192.168.10.0/24, 10.1.1.0/24, 172.16.0.0/24 via $WAN_IP\n";
echo "        plus pass rules permitting it. That leg is outside this script.\n";
echo "Verify in GUI: Interfaces > Assignments, Status > Gateways, Firewall > Rules.\n";