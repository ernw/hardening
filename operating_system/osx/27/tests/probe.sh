#!/bin/bash
# Read-only. Records command, output and exit code for every guide compliance
# command and VERIFY-27 item. Usage: ./probe.sh <output-dir>

set -u
. "$(dirname "$0")/lib.sh"

OUT="${1:?usage: $0 <output-dir>}"
mkdir -p "$OUT"
REPORT="$OUT/probe.txt"
: > "$REPORT"

# probe <tag> <title> <command> [timeout]; tags match the VERIFY-27 topics.
probe() {
  {
    printf '\n### [%s] %s\n$ %s\n' "$1" "$2" "$3"
    run_with_timeout "${4:-60}" /bin/bash -c "$3" 2>&1
    printf '(exit %s)\n' "$?"
  } >> "$REPORT"
}

REDACT="grep -viE 'serial|uuid|ecid|nonce|hash|udid|(lpnh|rpnh|ronh|vuid|kuid|nsih|spih)'"
FW=/usr/libexec/ApplicationFirewall/socketfilterfw

require_macos27
sudo_keepalive
log "Writing $REPORT"

probe system "macOS version" "sw_vers"
probe system "hardware" "system_profiler SPHardwareDataType | $REDACT"
probe system "MDM enrollment" "profiles status -type enrollment"

probe bputil "startup security policy" "sudo bputil -d | grep -E 'smb|sip|Security Mode|OS Version'"
probe sip "SIP" "csrutil status"
probe ssv "authenticated root" "csrutil authenticated-root status; mount | grep ' / '"
probe ssv "system volume writable" "system_profiler SPStorageDataType | awk '/Mount Point: \\/\$/{x=NR+2}(NR==x)'"
probe gatekeeper "status" "spctl --status --verbose"
probe gatekeeper "usage" "spctl 2>&1 | head -40"
probe filevault "status" "fdesetup status -extended"
probe filevault "recovery users" "sudo diskutil apfs listUsers / | grep -iE 'Type|Personal|Institutional'"
probe diagnostics "DiagnosticMessagesHistory" "defaults read /Library/Application\\ Support/CrashReporter/DiagnosticMessagesHistory.plist"
probe diagnostics "Siri data sharing" "defaults read com.apple.assistant.support 'Siri Data Sharing Opt-In Status'"
probe lockdown "LDMGlobalEnabled" "defaults read .GlobalPreferences LDMGlobalEnabled"
probe accessories "accessd" "sudo defaults read /Library/Preferences/com.apple.accessd"
probe securetoken "secure token" "sudo sysadminctl -secureTokenStatus \"\$(stat -f%Su /dev/console)\""
probe sysext "system extensions" "systemextensionsctl list"
probe persistence "non-Apple launchd jobs" "launchctl list | grep -v com.apple"
probe persistence "sfltool dumpbtm" "sudo sfltool dumpbtm | head -80"
probe persistence "quarantined launchd plists" "for f in /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist \$HOME/Library/LaunchAgents/*.plist; do [ -e \"\$f\" ] && xattr -l \"\$f\" | grep -q quarantine && echo \"\$f\"; done; true"
probe persistence "crashed system services" "sudo launchctl print system | grep -c 'state = crashed'"

probe pwpolicy "global policy" "sudo pwpolicy -getglobalpolicy"
probe pwpolicy "account policies" "sudo pwpolicy getaccountpolicies 2>&1 | head -40"
probe loginwindow "loginwindow" "defaults read /Library/Preferences/com.apple.loginwindow"
probe touchid "bioutil" "bioutil -r; bioutil -rs"
probe sudo "sudo -V" "sudo sudo -V | grep -iE 'timestamp|tty'"
probe sudo "sudoers.d" "sudo ls -la /etc/sudoers.d"
probe authdb "system.preferences" "security authorizationdb read system.preferences 2>/dev/null | grep -A1 '<key>shared</key>'"
probe pam "sudo / sudo_local" "cat /etc/pam.d/sudo; ls -la /etc/pam.d/sudo_local*"

probe updates "softwareupdate -l" "softwareupdate -l" 300
probe updates "history" "softwareupdate --history | head -22"
probe updates "com.apple.SoftwareUpdate" "defaults read /Library/Preferences/com.apple.SoftwareUpdate"
probe updates "com.apple.commerce" "defaults read /Library/Preferences/com.apple.commerce"
probe updates "state files" "sudo ls -la /var/db/softwareupdate/"
probe updates "DDM state" "sudo plutil -p /var/db/softwareupdate/SoftwareUpdateDDMStatePersistence.plist 2>&1 | head -80"
probe ntp "systemsetup" "sudo systemsetup -getnetworktimeserver; sudo systemsetup -getusingnetworktime"
probe ntp "timed" "sudo defaults read /Library/Preferences/com.apple.timed"

probe timemachine "destinations" "tmutil destinationinfo"
probe timemachine "DoNotOfferNewDisksForBackup" "defaults read com.apple.TimeMachine DoNotOfferNewDisksForBackup"
probe storage "APFS FileVault states" "diskutil apfs list | grep -E 'Name:|FileVault:|Role'"
probe diskimage "diskutil image" "diskutil image 2>&1 | head -60"
probe diskimage "diskutil image create" "diskutil image create 2>&1 | head -80"
probe diskimage "hdiutil deprecation" "hdiutil info 2>&1 | head -5"
probe finder "extensions / DS_Store" "defaults read NSGlobalDomain AppleShowAllExtensions; defaults read com.apple.desktopservices"
probe rosetta "presence" "pgrep -l oahd; ls -ld /Library/Apple/usr/libexec/oah; pkgutil --pkgs | grep -i rosetta; arch -x86_64 /usr/bin/true; echo \"arch -x86_64 rc=\$?\""
probe rosetta "application kinds" "system_profiler SPApplicationsDataType -detailLevel mini | grep 'Kind:' | sort | uniq -c" 300

probe firewall "socketfilterfw" "$FW --getglobalstate; $FW --getstealthmode; $FW --getblockall; $FW --getallowsigned; $FW --getloggingmode; $FW --getloggingopt"
probe firewall "pf" "sudo pfctl -s info 2>/dev/null | head -3"
probe powernap "pmset custom" "pmset -g custom"
probe powernap "pmset keys" "pmset -g | grep -iE 'powernap|womp'; pmset -g cap"
probe powernap "systemsetup wake" "sudo systemsetup -getwakeonnetworkaccess"
probe handoff "useractivityd" "defaults -currentHost read com.apple.coreservices.useractivityd"
probe airdrop "sharingd" "defaults read com.apple.sharingd"
probe airdrop "NetworkBrowser" "defaults read com.apple.NetworkBrowser"
probe sharing "print-disabled" "launchctl print-disabled system"
probe sharing "systemsetup remote" "sudo systemsetup -getremotelogin; sudo systemsetup -getremoteappleevents"
probe sharing "mdmclient" "sudo /usr/libexec/mdmclient QuerySecurityInfo 2>/dev/null | grep -E 'RemoteDesktop|SecureBoot|ExternalBoot|FDE_Enabled|SystemIntegrity|Firewall'"
probe sharing "cupsctl" "cupsctl"
probe sharing "content caching" "AssetCacheManagerUtil isActivated 2>&1; defaults read /Library/Preferences/com.apple.AssetCache.plist"
probe sharing "media sharing" "defaults read com.apple.amp.mediasharingd"
probe airplay "receiver" "defaults -currentHost read com.apple.controlcenter AirplayReceiverEnabled"
probe icloud "restrictions" "sudo profiles -P -o stdout 2>/dev/null | grep -E 'allow[A-Za-z]+ = '"
probe privaterelay "mask.icloud.com" "dscacheutil -q host -a name mask.icloud.com | wc -l"
probe ssh "version" "ssh -V"
probe ssh "algorithms" "for q in kex cipher mac key; do echo \"== \$q\"; ssh -Q \$q; done"
probe ssh "effective config" "ssh -G compliance-check.invalid | grep -E '^(ciphers|macs|kexalgorithms|hostkeyalgorithms|pubkeyacceptedalgorithms|securitykeyprovider) '"
probe ssh "Secure Enclave provider" "ls -l /usr/lib/ssh-keychain.dylib; man -w ssh-keychain sc_auth 2>&1; sc_auth 2>&1 | head -40"
probe pqc "nscurl" "nscurl --tls-diagnostics https://www.google.com 2>&1 | grep -iE 'key exchange|TLS version|ciphersuite' | head -20" 120
probe pqc "com.apple.network.tls" "defaults read com.apple.network.tls"
probe location "locationd" "sudo -u _locationd defaults read com.apple.locationd LocationServicesEnabled 2>&1; sudo find /private/var/db/locationd/Library/Preferences/ByHost -name 'com.apple.locationd.*.plist' -exec defaults read {} LocationServicesEnabled \;"

probe tcc "tccutil --info" "tccutil --info 2>&1 | head -60"
probe tcc "tccutil list (user)" "tccutil list 2>&1 | head -80"
probe tcc "tccutil list (root)" "sudo tccutil list 2>&1 | head -80"
probe tcc "TCC.db direct access" "sqlite3 \$HOME/Library/Application\\ Support/com.apple.TCC/TCC.db 'select count(*) from access'"
probe ai "preference domains" "defaults domains | tr ',' '\\n' | sed 's/^ *//' | grep -iE 'siri|assistant|intelligence|generative|writing|playground|screentime|familycontrols|ironwood'"
probe ai "com.apple.Siri" "defaults read com.apple.Siri"
probe ai "com.apple.assistant.support" "defaults read com.apple.assistant.support"
probe ai "com.apple.ironwood.support" "defaults read com.apple.ironwood.support"
probe ai "Siri processes" "pgrep -lf -i siri"

probe xprotect "version" "xprotect version"
probe xprotect "check" "sudo xprotect check" 120
probe xprotect "bundles" "defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist Version; defaults read /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist CFBundleShortVersionString"

probe homebrew "brew" "command -v brew && brew analytics state"
probe pki "ERNW roots" "security find-certificate -a -c 'ERNW' -Z /Library/Keychains/System.keychain 2>&1 | grep -E 'SHA-256|labl'"

log "Done: $(grep -c '^### ' "$REPORT") probes, $(grep -c '^(exit [1-9]' "$REPORT") with non-zero exit"
