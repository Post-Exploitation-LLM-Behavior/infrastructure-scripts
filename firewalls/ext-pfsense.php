<?php
/*
 * ext-pfsense.php
 * ---------------------------------------------------------------------------
 * Sets the internal and external interfaces to their proper values. External
 * will be assigned a dhcp IP from RLES, while the internal network will be
 * 172.16.10.0/24 with the internal interface having the 172.16.10.1 address.
 *
 * Detects the correct interfaces to use. WAN is NIC the default route uses
 * while the LAN is the NIC that can ARP the attack-net hosts (requires
 * attacker and langfuse machines to have IPs statically assigned beforehand.)
 *      This is necessary because RLES has some issues with interface swapping.
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
 * 
 * -d or --debug flag will give more verbose output
 * -l or --logging will enable logging on the created firewall rules
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

$DEBUG = in_array("-d", $argv, true) || in_array("--debug", $argv, true);
$LOGGING = in_array("-l", $argv, true) || in_array("--logging", $argv, true);

function dbg($msg) {
    global $DEBUG;
    if ($DEBUG) fwrite(STDOUT, "[debug] $msg\n");
}

// This might be helpful for future:
//   php -r 'require("config.inc"); print_r(get_configured_interface_with_descr());'
$WAN = "wan";
$LAN = "lan";

$LAN_TARGETS = array("172.16.10.10", "172.16.10.11");
$PROBE_IP = "172.16.10.250";

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

// variables needed to add exception to lab machines
$LAB_ALIAS_NAME  = "LAB_SUBNETS";
$LAB_RANGES      = "172.16.10.0/24 192.168.10.0/24 10.1.1.0/24 172.16.0.0/24";
$LAB_ALIAS_DESCR = "Lab infrastructure subnets (attack-net + int-net 1/2/3)";
$PASS_RULE_DESCR = "Allow internal attack-net -> lab subnets (infra exception)";

dbg("flags: debug=on, logging=" . ($LOGGING ? "on" : "off"));

// NIC detection function
function _nic_list() {
    $out = trim((string) shell_exec("ifconfig -l 2>/dev/null"));
    $all = preg_split('/\s+/', $out);
    return array_values(array_filter($all, function ($i) {
        return preg_match('/^(vmx|vtnet|em|igb|ix|re|bge)\d+$/', $i);
    }));
}
function _detect_wan_if() {
    return trim((string) shell_exec(
        "route -n get default 2>/dev/null | awk '/interface:/{print \$2}'"));
}
function _detect_lan_if($targets, $probe_ip, $prefix, $exclude) {
    foreach (_nic_list() as $if) {
        if ($if === $exclude) { dbg("  probe: skipping $if (already WAN)"); continue; }
        exec("ifconfig " . escapeshellarg($if) . " up 2>/dev/null");
        exec("ifconfig " . escapeshellarg($if) . " inet " .
             escapeshellarg("$probe_ip/$prefix") . " alias 2>/dev/null");
        $found = false; $hit = "";
        foreach ($targets as $t) {
            exec("arp -d " . escapeshellarg($t) . " 2>/dev/null");
            exec("ping -c1 -W1000 -S " . escapeshellarg($probe_ip) . " " .
                 escapeshellarg($t) . " >/dev/null 2>&1");
            $arp = (string) shell_exec("arp -n " . escapeshellarg($t) . " 2>/dev/null");
            if (preg_match('/([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}/', $arp, $m)) {
                $found = true; $hit = "$t at " . $m[0]; break;
            }
        }
        exec("ifconfig " . escapeshellarg($if) . " inet " .
             escapeshellarg($probe_ip) . " -alias 2>/dev/null");
        dbg("  probe: $if -> " . ($found ? "REACHED $hit" : "no reply from targets"));
        if ($found) return $if;
    }
    return "";
}

echo "[*] Auto-detecting interfaces (hosts " .
        implode(", ", $LAN_TARGETS) . " must be powered on)\n";
dbg("NICs found: " . implode(", ", _nic_list()));
if ($WAN_IF === "") {
    $WAN_IF = _detect_wan_if();
    echo "    WAN (default route)   : " . ($WAN_IF ?: "<none>") . "\n";
} else {
    echo "    WAN (manual override) : $WAN_IF\n";
}
if ($LAN_IF === "") {
    dbg("probing remaining NICs for one that reaches the attack-net hosts...");
    $LAN_IF = _detect_lan_if($LAN_TARGETS, $PROBE_IP, $LAN_SUBNET, $WAN_IF);
    echo "    LAN (reaches targets) : " . ($LAN_IF ?: "<none>") . "\n";
} else {
    echo "    LAN (manual override) : $LAN_IF\n";
}

if ($WAN_IF === "" || $LAN_IF === "") {
    fwrite(STDERR, "!! Interface detection failed. NOTHING WRITTEN.\n");
    fwrite(STDERR, "   - Are " . implode(", ", $LAN_TARGETS) .
                    " powered on and on Attacker_LAN?\n");
    fwrite(STDERR, "   - Is the WAN NIC up with a default route?\n");
    fwrite(STDERR, "   Or set \$WAN_IF/\$LAN_IF manually.\n");
    exit(1);
}
if ($WAN_IF === $LAN_IF) {
    fwrite(STDERR, "!! WAN and LAN resolved to the same NIC ($WAN_IF). Aborting.\n");
    exit(1);
}
echo "    => WAN=$WAN_IF  LAN=$LAN_IF\n";

// avoid double-binding
foreach (array_keys($config['interfaces'] ?? array()) as $lif) {
    if ($lif === $WAN || $lif === $LAN) continue;
    $boundIf = $config['interfaces'][$lif]['if'] ?? '';
    if ($boundIf !== '' && in_array($boundIf, array($WAN_IF, $LAN_IF), true)) {
        unset($config['interfaces'][$lif]);
        dbg("freed slot $lif (was bound to $boundIf)");
    }
}

// WAN config
if (!is_array($config['interfaces'][$WAN])) $config['interfaces'][$WAN] = array();
$config['interfaces'][$WAN]['enable'] = "";
$config['interfaces'][$WAN]['ipaddr'] = "dhcp";
if ($WAN_IF !== "") $config['interfaces'][$WAN]['if'] = $WAN_IF;
if (empty($config['interfaces'][$WAN]['descr'])) $config['interfaces'][$WAN]['descr'] = "WAN";
dbg("WAN slot '$WAN' -> if=$WAN_IF, ipaddr=dhcp");

// LAN config
if (!is_array($config['interfaces'][$LAN])) $config['interfaces'][$LAN] = array();
$config['interfaces'][$LAN]['enable'] = "";
$config['interfaces'][$LAN]['ipaddr'] = $LAN_IP;
$config['interfaces'][$LAN]['subnet'] = (string) $LAN_SUBNET;
if ($LAN_IF !== "") $config['interfaces'][$LAN]['if'] = $LAN_IF;
if (empty($config['interfaces'][$LAN]['descr'])) $config['interfaces'][$LAN]['descr'] = "ATTACKNET";
dbg("LAN slot '$LAN' -> if=$LAN_IF, ipaddr=$LAN_IP/$LAN_SUBNET");

// shut off DHCP
if (is_array($config['dhcpd']) && is_array($config['dhcpd'][$LAN])) {
    unset($config['dhcpd'][$LAN]['enable']);
    dbg("LAN DHCP server: disabled");
} else {
    dbg("LAN DHCP server: no dhcpd block present, nothing to disable");
}

$used = array($WAN_IF, $LAN_IF);
foreach ($config['interfaces'] as $lif => $ifc) {
    if ($lif === $WAN || $lif === $LAN) continue;
    if (preg_match('/^opt/', $lif) && !in_array($ifc['if'] ?? '', $used, true)) {
        unset($config['interfaces'][$lif]['enable']);
        dbg("disabled unused interface $lif (" . ($ifc['if'] ?? '?') . ")");
    }
}

// Alias config
if (!is_array($config['aliases'])) $config['aliases'] = array();
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
dbg("alias $ALIAS_NAME " . ($found ? "updated" : "created") . ": $RANGES");

// checking for alias about infrastructure
$labfound = false;
foreach ($config['aliases']['alias'] as &$a) {
    if (($a['name'] ?? '') === $LAB_ALIAS_NAME) {
        $a['type'] = "network"; $a['address'] = $LAB_RANGES; $a['descr'] = $LAB_ALIAS_DESCR;
        $labfound = true; break;
    }
}
unset($a);
if (!$labfound) {
    $config['aliases']['alias'][] = array(
        'name' => $LAB_ALIAS_NAME, 'type' => "network",
        'address' => $LAB_RANGES, 'descr' => $LAB_ALIAS_DESCR,
    );
}
dbg("alias $LAB_ALIAS_NAME " . ($labfound ? "updated" : "created") . ": $LAB_RANGES");

// Firewall block rule
if (!is_array($config['filter'])) $config['filter'] = array();
if (!is_array($config['filter']['rule'] ?? null)) $config['filter']['rule'] = array();

// Keep the existing rule's tracker so log entries still map to it across reruns
$tracker = (string) time();
$reused = false;
foreach ($config['filter']['rule'] as $r) {
    if (($r['descr'] ?? '') === $RULE_DESCR && !empty($r['tracker'])) {
        $tracker = $r['tracker']; $reused = true; break;
    }
}

// remove the old rule if it exists
$before = count($config['filter']['rule']);
$config['filter']['rule'] = array_values(array_filter(
    $config['filter']['rule'],
    function ($r) use ($RULE_DESCR) { return ($r['descr'] ?? '') !== $RULE_DESCR; }
));
dbg("block rule: " . ($before > count($config['filter']['rule']) ? "replaced existing" : "new") .
    ", tracker=$tracker" . ($reused ? " (reused)" : "") . ", logging=" . ($LOGGING ? "on" : "off"));


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
if ($LOGGING) $rule['log'] = "";

// Put this at the front of the rules
array_unshift($config['filter']['rule'], $rule);

// adding the alias to allow for traffic to infrastructure
$pass_tracker = (string) time();
foreach ($config['filter']['rule'] as $r) {
    if (($r['descr'] ?? '') === $PASS_RULE_DESCR && !empty($r['tracker'])) {
        $pass_tracker = $r['tracker']; break;
    }
}
$config['filter']['rule'] = array_values(array_filter(
    $config['filter']['rule'],
    function ($r) use ($PASS_RULE_DESCR) { return ($r['descr'] ?? '') !== $PASS_RULE_DESCR; }
));
$pass = array(
    'type'        => "pass",
    'interface'   => $LAN,
    'ipprotocol'  => "inet",
    'source'      => array('network' => $LAN),
    'destination' => array('address' => $LAB_ALIAS_NAME),
    'descr'       => $PASS_RULE_DESCR,
    'tracker'     => $pass_tracker,
);
if ($LOGGING) $pass['log'] = "";
array_unshift($config['filter']['rule'], $pass);
dbg("pass rule (lab exception) placed above block: {$LAN} net -> {$LAB_ALIAS_NAME}");

// check to see if admin password is valid
if (!preg_match('/^\$2y\$\d{2}\$[.\/A-Za-z0-9]{53}$/', $ADMIN_PW)) {
    fwrite(STDERR, "ADMIN_PW is not a bcrypt hash (\$2y\$...), aborting before writing config.\n");
    exit(1);
}
dbg("admin hash validation passed");

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
dbg("admin account '{$admin['name']}' (uid 0): bcrypt-hash replaced, other hashes cleared");

// Commit & apply changes
dbg("committing config (write_config)...");
write_config("lab setup: wan dhcp, lan static {$LAN_IP}/{$LAN_SUBNET} (no dhcpd), containment rule, admin password");

local_user_set($admin);         // syncs the hash to /etc/master.passwd (console/SSH root too)
dbg("local_user_set: admin hash synced to /etc/master.passwd");

interface_configure($WAN, true);
interface_configure($LAN, true);
dbg("interfaces reconfigured: $WAN ($WAN_IF), $LAN ($LAN_IF)");
services_dhcpd_configure();     // realizes the DHCP-server-off state
dbg("dhcpd reconfigured");
filter_configure();
dbg("filter reloaded");
echo "Done.\n";
echo "  WAN  ({$WAN}): DHCP client\n";
echo "  LAN  ({$LAN}): {$LAN_IP}/{$LAN_SUBNET}, DHCP server disabled\n";
echo "  Rules: pass {$LAN} net -> {$LAB_ALIAS_NAME}  THEN  block {$LAN} net -> {$ALIAS_NAME}\n";
echo "  Admin: password hash replaced\n";

if ($DEBUG) {
    echo "\n[debug] results summary\n";
    echo "[debug]   WAN if      : " . ($config['interfaces'][$WAN]['if'] ?? '?') .
         "  ipaddr=" . ($config['interfaces'][$WAN]['ipaddr'] ?? '?') . "\n";
    echo "[debug]   LAN if      : " . ($config['interfaces'][$LAN]['if'] ?? '?') .
         "  ipaddr=" . ($config['interfaces'][$LAN]['ipaddr'] ?? '?') .
         "/" . ($config['interfaces'][$LAN]['subnet'] ?? '?') . "\n";
    echo "[debug]   pass rule   : src=" . $LAN . " net  dst=" . $LAB_ALIAS_NAME . "  (above block)\n";
    echo "[debug]   block rule  : src=" . $LAN . " net  dst=" . $ALIAS_NAME .
         "  log=" . ($LOGGING ? "yes" : "no") . "\n";
    echo "[debug]   total rules on all interfaces: " . count($config['filter']['rule']) . "\n";
}

echo "Verify: Firewall > Rules (attack-net), Status > Interfaces, Status > System Logs > Firewall.\n";