# Table of Content

1. [Introduction](#introduction)
1. [Authentication](#authentication)
 1. [Ensure Security of Standard and Default Accounts](#ensure-security-of-standard-and-default-accounts)
 1. [Users Privilege Separation](#users-privilege-separation)
 1. [Ensure Password Security](#ensure-password-security)
 1. [Enforce Password Security](#enforce-password-security)
 1. [Two Factor Authentication](#two-factor-authentication)
 1. [Automatic Login and User Lists](#automatic-login-and-user-lists)
 1. [Guest Accounts](#guest-accounts)
 1. [Restrict Sudoers file](#restrict-sudoers-file)
 1. [Automatically Lock the Login Keychain](#automatically-lock-the-login-keychain)
1. [General Configuration](#general-configuration)
 1. [Gatekeeper](#Gatekeeper)
 1. [Disable Diagnostics](#disable-diagnostics)
 1. [Disable Handoff](#disable-handoff)
 1. [Tracking Services](#tracking-services)
 1. [FileVault](#FileVault)
 1. [Firewall](#Firewall)
 1. [Require Administrator Password](#require-administrator-password)
 1. [Screensaver and Un-locking](#screensaver-and-un-locking)
 1. [Filename Extensions](#filename-extensions)
 1. [System Updates](#system-updates)
 1. [Prevent Safari from Opening Known File Types](#prevent-safari-from-opening-known-file-types)
 1. [Set Strict Global Umask](#set-strict-global-umask)
1. [Technical Configuration](#technical-configuration)
 1. [Disable Bluetooth](#disable-bluetooth)
 1. [Firmware Password](#firmware-password)
 1. [Setuid and Setgid](#setuid-and-setgid)
 1. [Disable Core Dumps](#disable-core-dumps)
1. [Network and Communication Security](#network-and-communication-security)
 1. [Advanced Firewall](#advanced-firewall)
 1. [Disable Wake on Lan](#disable-wake-on-lan)
 1. [Disable Apple File Protocol (AFP)](#disable-apple-file-protocol)
 1. [Disable Unnecessary Services](#disable-unnecessary-services)
 1. [Disable Sharing](#disable-sharing)
 1. [Harden TCP/IP Kernel Parameters](#harden-TCP/IP-kernel-parameters)
 1. [Enable Network Time Synchronization via NTP](#enable-network-time-synchronization-via-NTP)
 1. [Disable Bonjour (mDNS)](#disable-bonjour/mDNS)
1. [Recommended Applications](#recommended-applications)
 1. [Little Snitch](#little-snitch)
 1. [Micro Snitch](#micro-snitch)
 1. [BlockBlock](#BlockBlock)
 1. [Lockdown](#Lockdown)
 1. [RansomWhere?](#RansomWhere?)
 1. [Dylib Hijack Scanner](#dylib-hijack-scanner)
 1. [Lynis](#Lynis)
1. [Appendix: List of Services](#appendix-list-of-services)



# Introduction

ERNW has compiled the most relevant settings for OS X 10.11 El Captain into this compilation of security recommendations. This document is supposed to provide a solid base of hardening measures to enhance the system security and still remaining commonly applyable.
Settings which might have severe impact on the functionality of the operating system and need a lot of further testing are not part of this checklist or marked as optional.
We have marked each recommended setting in this checklist either with “mandatory” or “optional” to make a clear statement, which setting is a MUST (mandatory) or a SHOULD (optional) from our point of view. “Optional” also means that we recommend to apply this setting, but there may be required functionality on the system that will become unavailable once the setting is applied.
Important: This Guide will force you to Disable SIP (System Integrity Protection) a few times. After the hardening is done, please make sure you enable SIP again.

# Authentication

## Ensure Security of Standard and Default Accounts

OS X will always force you to create a new Account. Even if you run on an Admin Account, you won´t have the same rights as “root”.

This is what OS X calls System Integrity Protection (further in short SIP). SIP will deny any Change on System files like /etc/hosts.

> __!__ But there is local per User hosts file "/private/etc/hosts"

---

## Users Privilege Separation

It is suggested to use different accounts for administration and daily activities. Create an account with admin privileges for special tasks and maintenance and a normal user for your daily use to avoid fast elevation of privileges for Attackers.

---

## Ensure Password Security

Choosing a strong Password is Mandatory for the System. This Password Policy will give you a little hint for the minimum requirements.
*	Minimum password length of  at least 8 characters
*	Password must consist of at least one character of each character group (letters, capital letters, numbers, special characters)
*	Must not contain any default passwords
*	Must consist of at least 6 different characters
*	Should have a maximum age of 180 days
*	Username must not be part of password
*	At least the 5 previous passwords must not be (nearly) equal.

---

## Enforce Password Security

You can enforce a Password policy with the command line tool pwpolicy. The following Command enforces the above Policy:

> pwpolicy -u <user> -setpolicy "minChars=8 requiresAlpha=1 requiresNumeric=1 maxMinutesUntilChangePassword=259200 usingHistory=5 usingExpirationDate=1 passwordCannotBeName=1 requiresMixedCase=1 requiresSymbol=1"

---

## Two Factor Authentication

Since OS X 10.11 and IOS 9 these Devices have a built in two factor authentication mechanism which will secure your AppleID. If you want to access anything which will require you to login to your AppleID, Numbers for the Authentication will be pushed on another Device with either OS X 10.11 or IOS 9. This can affect your OS X installation, since it is possible to reset the password of the device from your AppleID.

If you are actively using your AppleID for various tasks it is recommended to use Two Factor Authentication.

---

## Automatic Login and User Lists

It is recommended to disable User listing. This will lower the chances of Attackers to guess the correct login credentials.

* System Preferences → Users & Groups → Login Options
* Set "Automatic login" to disabled
* Set "Display login window" to "Name and password"
* Disable Password hints

---

## Guest Accounts

Always disable everything for Guest Accounts and deactivate the Guest Account.

* System Preferences → Users & Groups
* Make sure Guest Users are disabled

---

## Restrict Sudoers file

To restrict the grace period and limit it to individual ttys. Edit /etc/sudoers and add the following:

```
Defaults timestamp_timeout=0
Defaults tty_tickets
```

---

## Automatically Lock the Login Keychain

* Open Keychain Access and select the login Keychain
* Choose Edit → Change Settings for Keychain "Login"
* Set Lock after [...] minutes of inactivity to 10
* Check "Lock when sleeping"

---

# General Configuration

## Gatekeeper
Gatekeeper will check if the Application is signed with a valid Apple Certificate. Checking Applications for the Signature is possible with:
> spctl –a /Applications/test.app

If you want add it to Gatekeeper you can use:

> spctl --add test.app

or simply

* right click → open.  

> __!__ Sometimes it will still deny opening the Application. You can then force the start:
* System Preferences → Security & Privacy → General  
* Open "Application"

---

## Disable Diagnostics
To avoid sending data to Apple or App Developers disable the following:

* System Preferences → Security & Privacy → Privacy → Diagnostics & Usage
* Uncheck “Send diagnostic & usage data to Apple”
* Uncheck “Share crash data with app developers”.

---

## Disable Handoff
Apples Handoff is a feature to keep your workspaces in sync but it does require to send data to Apple which is recommended to be disabled.

* System Preferences → General
* Uncheck “Allow Handoff between this Mac and your iCloud devices”
* Set “Recent Items” to none. You will find this inside of the dropdown box right above the Handoff option.

---

## Tracking Services

It is recommended to disable the Tracking Services. If you decide to use the Tracking Services it is possible to disable it just for the Spotlight Suggestions.

* System Preferences → Security & Privacy → Privacy → Location Services
* Select "System Services" → Details
* Uncheck "Spotlight Suggestions"

---

## FileVault
It is recommended to enable FileVault to use full disk encryption on your device. It should be already enabled by default.

* System Preferences → Security & Privacy → FileVault
* Enable FileVault

---

##  Firewall
It is recommended to enable the Firewall with full functionality and block all incoming traffic.

* System Preferences → Security & Privacy → Firewall
* Click on "Turn on Firewall"
* Click on "Firewall options"
* Set "Block all incoming connections"

---
## Require Administrator Password
It is recommended to always require the administrator password to access system settings.

* System Preferences → Security & Privacy → Advanced
* Set “Require an administrator password to access system-wide preferences”

---

## Screensaver and Un-locking
It is recommended to automatically lock your screen when inactive.

* System Preferences → Desktop & Screensaver → Screensaver
* Adjust the timeframe to your needs but we recommend to set it to 5 minutes.
* System Preferences → Security & Privacy → General
* Set "Require password immediately after sleep or screen saver begins"

---

## Filename Extensions

To be always clear what sort of file you´re processing. It is recommended to turn on Filename extensions.

* Open Finder → Settings → Advanced
* Set "Show all filename extensions"

---

## System Updates

To make sure Apple always installs the recent Security Updates and Malware blacklists make sure the Autoupdate is enabled.
* System Preferences → App Store
* Set "Automatically check for updates"
* Set all items within the "Automatically check for updates" context

> __!__ Apples standard update Procedure launches every 7 Days.
This can be changed under:

> ~/Library/Preferences/com.apple.scheduler.plist

> Open it with X Code
* Root → AbsoluteSchedule → com.apple.SoftwareUpdate → SUCheckSchedulerTag → Timer

> Right beneath the Date is an option for “repeatInterval” change the Value(in Seconds) according to your needs. E.G 172800 would be an Interval of 2 Days.

---

## Prevent Safari from Opening Known File Types

If you are using Safari as your main Browser it is recommended to prevent Safari from opening known files after downloading.

* Open Safari → Preferences → General
* Unset "Open safe files after downloading"

---

## Set Strict Global Umask
The Strict Global Umask defaults the Permission of any File or Directory which is created by a user. You can adjust the Global Umask with the following command:

> sudo launchctl config system umask 027

 > __!__ This might break the installation of additional Software that relies on a less restrict umask.


# Technical Configuration

## Disable Bluetooth
It is recommended to disable Bluetooth while it is not used.

* System Preferences → Bluetooth
* Deactivate Bluetooth

---

## Firmware Password

To prevent Single User Mode and bootable devices it is recommended to set a sufficient complex Firmware Password.

* Boot your Mac into Recovery Mode by pressing Command + R as your Mac is booting.
* Select Utilities → Firmware Password Utility
* Set a sufficient complex Password

---

## Setuid and Setgid
Altering the Setuid bits of binaries can be an important step. This may affect or break functionality on these binaries but you can always reverse these Steps. Use the following Command to get a list of all SUID binaries.

> sudo find / -perm -04000 -ls

> sudo find / -perm -02000 -ls

Filter out Applications where you suspect “Bad code quality” or you generally don´t trust (E.G. peripheral device driver of your mouse).

The following commands unset the described permissions on files and directories.

> chmod u-s #file

> chmod g-s #file


## Disable Core Dumps
To limit Kernel Information leaks disable the core dumping capability. Edit the following line in /etc/sysctl.conf:

> kern.coredump=0

> __!__ On a fresh installed system it is possible that sysctl.conf is not existent. If so you can create it and reboot the system.
Since Kerneldumps can be helpful for debugging you can enable it temporarily with:

> sudo sysctl -w kern.coredump=1

---


# Network and Communication Security

## Advanced Firewall

It is recommended to monitor more precise on Application Traffic. Such Software Firewalls can generate their own rulesets for different Locations and Networks.

We can recommend a more Advanced Firewall like “Little Snitch” which is full blown local Firewall (25-35€). If you are looking for a free alternative you can look at the lite version of “Murus”.

* https://www.obdev.at/products/littlesnitch/index-de.html
* http://www.murusfirewall.com/

---

## Disable Wake on Lan

* System Preferences → Energy Saver
* Unset "Wake for network access"

---

## Disable Apple File Protocol (AFP)

Apples equivalent to SMB. It is disabled by default on OS X 10.11. You can verify this under:

* System Preferences → Sharing
* Select "File Sharing" → Options
* Unset "Share Files and folders using AFP"

> __!__ You can disable it on the Command-Line:

>sudo launchctl unload -w /System/Library/LaunchAgents/AppleFileServer.plist

---

## Disable Unnecessary Services

you can disable unnecessary services by issuing the following command:

> sudo launchctl unload -w /System/Library/LaunchAgents/<Service

 We attached a List of Services that may be unnecessary for your installation.

> __!__ This can break functionality on the System. To load them back up just replace “unload” with “load”.

More Services can be Found in the following directories:

Servicefiles (Plistfiles) are located in
- /System/Library/LaunchDaemons
- /System/Library/LaunchAgents
- /Library/LaunchDaemons
- /Library/LaunchAgents
- /Users/USERNAME/Library/LaunchDaemons
- /Users/USERNAME/Library/LaunchAgents

---

## Disable Sharing
Sharing is disabled on default. You can verify this here:

* System Preferences → Sharing
* Unset everything which is not needed

---

## Harden TCP/IP Kernel Parameters
To harden your TCP/IP Stack you can set the following Kernel Parameters inside of /etc/sysctl.conf.

```
net.inet.ip.fw.verbose = 1
net.inet.ip.fw.verbose_limit = 65535
net.inet.icmp.icmplim = 1024
net.inet.icmp.drop_redirect = 1
net.inet.icmp.log_redirect = 1
net.inet.ip.redirect = 0
net.inet.ip.sourceroute = 0
net.inet.ip.accept_sourceroute = 0
net.inet.icmp.bmcastecho = 0
net.inet.icmp.maskrepl = 0
net.inet.tcp.delayed_ack = 0
net.inet.ip.forwarding = 0
net.inet.tcp.strict_rfc1948 = 1
```

> __!__ for IPv6 we can refer to our own Hardening Guide for OS X which can be found here: https://www.ernw.de/download/ERNW_Hardening_IPv6_MacOS-X_v1_0.pdf

---

## Enable Network Time Synchronization via NTP
To secure your clock is always correct and not corrupted for e.g Log-Files. Use the following Commands:

>sudo systemsetup -setnetworktimeserver "time.euro.apple.com"<br>
sudo systemsetup -setusingnetworktime on <br>
echo "restrict default ignore" >> /etc/ntp.conf

---

## Disable Bonjour (mDNS)

To secure mDNS you need to first disable SIP (System Integrity Protection). For this you need to restart your Mac and hold Command + r. When you land in the Recovery Section go to Utilities => Terminal and enter the following Command:

> csrutil disable

Now Restart your Mac again and issue the following command:

> sudo defaults write /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist ProgramArguments -array-add "-NoMulticastAdvertisements"

> __!__ Don´t forget to enable SIP again.  
Another Method is to disable all Multicast packets via Little Snitch.

---

# Recommended Applications

## Little Snitch
Little Snitch is a host-based application firewall for Mac OS X. As already described it can be used to monitor applications traffic more closely and prevent or permitting them to communicate their traffic through advanced rules.

Little Snitch controls the network traffic via the standard application programming interface (API) provided by Apple

If an application or process attempts to establish a network connection, Little Snitch prevents the connection. A dialog is presented which allows one to deny or permit the connection on a one-time or permanent basis. The dialog allows one to restrict the parameters of the connection, restricting it to a specific port, protocol or domain. Little Snitch's integral network monitor allows one to see ongoing traffic in real time with domain names and traffic direction displayed.

https://www.obdev.at/products/littlesnitch/index.html

## Micro Snitch
Micro Snitch can be additionally purchased to Little Snitch. It will monitor when an application is trying to access either the microphone or the camera and display it to the user.

https://www.obdev.at/products/microsnitch/index.html

## BlockBlock

Malware installs itself persistently, to ensure it's automatically re-executed at reboot. BlockBlock continually monitors common persistence locations and displays an alert whenever a persistent component is added to the OS.

https://objective-see.com/products/blockblock.html

## Lockdown
Lockdown is an open-source tool for El Capitan that audits and remediates security configuration settings.
Written as a UI wrapper for Summit Route's open-source 'osxlockdown' tool, Lockdown helps to secure OS X computers by reducing their attack surface.

https://objective-see.com/products/lockdown.html

## RansomWhere?
By continually monitoring the file-system for the creation of encrypted files by suspicious processes, RansomWhere? aims to protect your personal files, generically stopping ransomware in its tracks.

https://objective-see.com/products/ransomwhere.html

## Dylib Hijack Scanner
Dylib Hijack Scanner or DHS, is a simple utility that will scan your computer for applications that are either susceptible to dylib hijacking or have been hijacked.

https://objective-see.com/products/dhs.html

## Lynis
Lynis is an open source security auditing tool. Used by system administrators, security professionals, and auditors, to evaluate the security defenses of their Linux and UNIX-based systems. It runs on the host itself, so it performs more extensive security scans than vulnerability scanners.

https://cisofy.com/lynis/



---


# Appendix List of Services

The following table lists service files and the corresponding
functionality that should be disabled/must not be enabled unless
required.

Example for table:

| **Filename**  | **Functionality** |
| ------------- |:-------------:|
|  com.apple.AppleFileServer.plist    | AFP           |
| ftp.plist | FTP |
| smbd.plist    | SMB|
|  org.apache.httpd.plist| HTTP Server|
| eppc.plist                  |                   Remote Apple Events|
| com.apple.xgridagentd.plist    |                Xgrid|
| com.apple.xgridcontrollerd.plist|               Xgrid|
| com.apple.InternetSharing.plist |               Iternet Sharing|
| com.apple.dashboard.advisory.fetch.plist  |     Dashboard Auto-Update|
| com.apple.UserNotificationCenter.plist      |   User notifications|
| com.apple.RemoteDesktop.PrivilegeProxy.plist|   ARD|
| com.apple.RemoteDesktop.plist               |   ARD|
| com.apple.IIDCAssistant.plist                |  iSight|
| com.apple.blued.plist                         | Bluetooth|
| com.apple.RemoteUI.plist                      | Remote Control|
| com.apple.gamed.plist | Game Center |
| com.apple.netbiosd.plist | NetBios |
