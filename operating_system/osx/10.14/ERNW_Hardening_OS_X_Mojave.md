# Table of Content

<!-- TOC depthFrom:2 -->

- [1. Introduction](#introduction)
- [2. General Recommendations](#general-recommendations)
    - [2.1. Secure Boot](#secure-boot)
    - [2.2. End-Point Protection](#end-point-protection)
    - [2.3. Logging and Event Collection](#Logging-and-Event-Collection)
    - [2.4. Mobile Device Management](#Mobile-Device-Management)
- [3. Authentication](#Authentication)
    - [3.1. Ensure Security of Standard and Default Accounts](#Ensure-Security-of-Standard-and-Default-Accounts)
    - [3.2. Users Privilege Separation](#Users-Privilege-Separation)
    - [3.3. Ensure Password Security](#Ensure-Password-Security)
    - [3.4. Enforce Password Security (Mandatory)](#Enforce-Password-Security-(Mandatory))
    - [3.4. Two Factor Authentication (Optional)](#Two-Factor-Authentication-(Optional))
    - [3.5. Automatic Login and User List (Mandatory)](#Automatic-Login-and-User-List-(Mandatory))
    - [3.6. Login Banner (Optional)](#Login-Banner-(Optional))
    - [3.7. Guest Accounts (Mandatory)](#Guest-Accounts-(Mandatory))
    - [3.8. Restrict Sudoers file (Mandatory)](#Restrict-Sudoers-file-(Mandatory))
    - [3.9. Automatically Lock the Login Keychain (Optional)](#Automatically-Lock-the-Login-Keychain (Optional))
- [4. General Configuration](#General-Configuration)
    - [4.1. Patching the current system (Mandatory)](#Patching-the-current-system-(Mandatory))
    - [4.2. Auto Updates (Mandatory)](#Auto-Updates-(Mandatory))
    - [4.3. Gatekeeper (Mandatory)](#Gatekeeper-(Mandatory))
    - [4.4. Enforcing Code Signing (Mandatory)](#Enforcing-Code-Signing-(Mandatory))
    - [4.5. Disable Creation of Metadata Files (Mandatory)](#Disable-Creation-of-Metadata-Files-(Mandatory))
    - [4.6. Disable saving to iCloud (Mandatory)](#Disable-saving-to-iCloud-(Mandatory))
    - [4.7. Disable Diagnostics (Mandatory)](#Disable-Diagnostics-(Mandatory))
    - [4.8. Disable Handoff (Mandatory)](#Disable-Handoff-(Mandatory))
    - [5.9. FileVault (Mandatory)](#FileVault-(Mandatory))
    - [5.10. Firewall (Mandatory)](#Firewall-(Mandatory))
    - [5.11. Require Administrator Password (Mandatory)](#Require-Administrator-Password-(Mandatory))
    - [5.12. Screensaver and Un-locking (Mandatory)](#Screensaver-and-Un-locking-(Mandatory))
    - [5.13. Filename Extensions (Mandatory)](#Filename-Extensions-(Mandatory))
    - [5.14. Prevent Safari from Opening Known File Types (Mandatory)](#Prevent-Safari-from-Opening-Known-File-Types-(Mandatory))
    - [5.15. Set Strict Global Umask (Optional)](#Set-Strict-Global-Umask-(Optional))
    - [5.16. Disable Remote Apple Events (Mandatory)](#Disable-Remote-Apple-Events-(Mandatory))

- [6.Technical Configuration](#Technical-Configuration)
    - [6.1. Disable Bluetooth (Optional)](#Disable-Bluetooth-(Optional))
    - [6.2. Firmware Password (Mandatory)](#Firmware-Password-(Mandatory))
    - [6.3. Setuid and Setgid (Optional)](#Setuid-and-Setgid-(Optional))
    - [6.4. Disable Core Dumps (Mandatory)](#Disable-Core-Dumps-(Mandatory))
    - [6.5. Disabling USB/Bluetooth and other mass storage peripherals (Optional)](#Disabling-USB/Bluetooth-and-other-mass-storage-peripherals-(Optional))
- [7. Network and Communication Security](#Network-and-Communication-Security)
    - [7.1. Advanced Firewall (Optional)](#Advanced-Firewall-(Optional))
    - [7.2. Disable Wake on Lan (Mandatory)](#Disable-Wake-on-Lan-(Mandatory))
    - [7.3. Disable Apple File Protocol (AFP) (Mandatory)](#Disable-Apple-File-Protocol-(AFP)-(Mandatory))
    - [7.4. Disable Unnecessary Services (Optional)](#Disable-Unnecessary-Services-(Optional))
    - [7.5. Disable Sharing (Mandatory)](#Disable-Sharing-(Mandatory))
    - [7.6. Enable Network Time Synchronization via NTP (Mandatory)](#Enable-Network-Time-Synchronization-via-NTP-(Mandatory))
- [8. Privacy](#Privacy)
    - [8.1. Computer-/Hostname (Mandatory)](#Computer-/Hostname-(Mandatory))
    - [8.2. Limit Ad Tracking (Mandatory)](#Limit-Ad-Tracking-(Mandatory))
    - [8.3. Tracking Services (Mandatory)](#Tracking-Services-(Mandatory))

- [9. Appendix List of Services](#Appendix-List-of-Services)


 
# Introduction

This document provides a base hardening guideline for Mac OS 10.14  to enhance the system security and still remaining commonly usable. 
Settings which might have severe impact on the functionality of the operating system and need a lot of further testing are not part of this checklist or marked as optional. 
We have marked each recommended setting in this checklist either with “mandatory” or “optional” to make a clear statement, which setting is a MUST (mandatory) or a SHOULD (optional) from our point of view. “Optional” also means that we recommend applying this setting, but there may be required functionality on the system that will become unavailable once the setting is applied. Further, we will mark the “Optional” setting if  it has a big impact on the user experience.
Important: This guide will force you to Disable SIP [1] (System Integrity Protection) a few times. After the hardening is done, please make sure you enable SIP again.

[1] - http://osxdaily.com/2015/10/05/disable-rootless-system-integrity-protection-mac-os-x/

---

# General Recommendations

This chapter describes general approaches for the Mac OS system.

---

## Secure Boot

The new 2018 MacBook models support secure boot through their newly included T2 chip inside the ```TouchBar``` including the Secure Enclave. To check if Secure Boot is enabled, the MacBook needs to be booted with the ```cmd+r``` key. After entering the Firmware Password, it is possible to access the “Startup Security Utility” in the Menu bar. If the MacBook contains a T2 Chip (```TouchBar```), it is possible to see the options for “Secure Boot” and “External Boot”. It is highly recommended to have “Secure Boot” on Full Security and “External Boot” on Disallow booting from external media.

---

## End-Point Protection

Per default, Mac OS has already protection mechanisms such as XProtect (Malware detection), Secure Boot, Codesigning validation, Sandboxed Application and System Integrity Protection in place. Further, if an MDM is enabled (e.g. Mac OS Server), the devices can be configured and managed through different policies.
If it is required to have additional end-point protection tools installed, it should be evaluated if already used tools support Mac OS devices. Otherwise, such managed software can be evaluated. 
 
---

## Logging and Event Collection


The audit framework of MacOS can be granularly configured. The aggregated logs can be viewed with the application ```/Applications/Utilities/Console.app.```. 
MacOS per default supports sending logs over UDP (Port 514) through the syslogd daemon. However, it is not recommended to use this feature due to the lack of support for TLS/SSL and will be soon deprecated by Apple. 
If your company does not possess a SIEM which supports Mac OS with agents, it is recommended to only aggregate logs locally from the MacBook and prevent sending unencrypted logs over the wire.
It is possible to obtain such logs in a sane and secure way using the log utility provided by Mac OS. A requirement is that the receiving end of a log aggregation server has a TCP port open which supports TLS/SSL. 
The following command on the MacBook will for example send every failed sudo try to the log server over an encrypted channel:

```
log stream --style syslog --predicate 'process == "sudo" and eventMessage contains "incorrect password"' | openssl s_client -host <RemoteServer> -port <Port>
```
The log server would receive a similar log message as shown below:
```
Filtering the log data using "process == "sudo" AND composedMessage CONTAINS "incorrect password""
Timestamp                       (process)[PID]
2018-10-24 17:23:33.842651+0200  localhost sudo[2002]:   MacBook_ERNW : 2 incorrect password attempts ; TTY=ttys002 ; PWD=/Users/MacBook_ERNW ; USER=root ; COMMAND=su
```
Such log streams can be automatically launched using the Mac OS Login items. 
Further, it should be evaluated which filters should be used for the log aggregation.  

---

## Mobile Device Management

Connecting the MacBook with a Mobile Device Management System (MDM) like the Mac OS Server, it is possible to force the operating system to follow provided policies. Further, deploying certificates and connection towards an Active Directory is possible over MDM solutions. 

---

# Authentication

## Ensure Security of Standard and Default Accounts

Mac OS will always force you to create a new Account. Even if you run on an Admin Account, you won´t have the same rights as “root”.
This is what MAC OS calls System Integrity Protection (further in short SIP). SIP will deny any Change on System directories like ```/System```.

---

## Users Privilege Separation

It is suggested to use different accounts for administration and daily activities. Create an account with admin privileges for special tasks and maintenance and a normal user for your daily use to avoid fast elevation of privileges by attackers.

---

## Ensure Password Security

Choosing a strong Password is Mandatory for the System. In case there is currently no Password Policy in place, the following Policy shall be used as the minimum requirements:

* Minimum password length of at least 8 characters
* Password must consist of at least one character of each character group (letters, capital letters, numbers, special characters)
* Must not contain any default passwords
* Must consist of at least 6 different characters
* Should have a maximum age of 180 days
* Username must not be part of password
* At least the 5 previous passwords must not be (nearly) equal.

---

## Enforce Password Security (Mandatory)

You can enforce a Password policy with the command line tool ```pwpolicy```. 
Since Mojave deprecated some commands in ```pwpolicy``` the following workaround can be used to set a policy globally.

It is still possible to set a password policy on a dedicated user using the following Command: 
```
pwpolicy -u <user> -setpolicy "minChars=8 requiresAlpha=1 requiresNumeric=1 maxMinutesUntilChangePassword=259200 usingHistory=5 usingExpirationDate=1 passwordCannotBeName=1 requiresMixedCase=1 requiresSymbol=1"
```

It is now possible to extract the policy to a file using the following command:

```
pwpolicy getaccountpolicies -u <user> > pwpolicy.plist
```

It is necessary to delete the following line in the file which was generated by the previous command: 
```
Getting account policies for user <user>
```

Now the generated password policy can be loaded using the following command as the ```root``` user:

```
pwpolicy setaccountpolicies pwpolicy.plist
```


---

## Two Factor Authentication (Optional)

Since MAC OS 10.11 and IOS 9, these Apple Devices have a built-in two factor authentication mechanism which will secure your AppleID. If you want to access anything that requires a login to your AppleID, Numbers for the Authentication will be pushed on another Device with either MAC OS 10.11 or IOS 9. This can affect your MAC OS installation, since it is possible to reset the password of the device from your AppleID.
If you are actively using your AppleID for various tasks, it is recommended to use Two Factor Authentication.

---

## Automatic Login and User List (Mandatory)

It is recommended to disable User listing. This will lower the chances of Attackers to guess the correct login credentials.

* System Preferences → Users & Groups → Login Options
* Set "Automatic login" to disabled
* Set "Display login window" to "Name and password"
* Disable Password hints

---

## Login Banner (Optional)

It is possible to set a Login Banner (similar to the Message of the Day) to display a message containing policies at login.
```
sudo defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText “text” 
```
---

## Guest Accounts (Mandatory)

Always disable everything for Guest Accounts and deactivate the Guest Account.

* System Preferences → Users & Groups
* Make sure Guest Users are disabled

---

## Restrict Sudoers file (Mandatory)

To restrict the grace period and limit it to individual ttys edit ```/etc/sudoers``` with the ```visudo``` command and add the following:
```
Defaults timestamp_timeout=0
Defaults tty_tickets
```

---

## Automatically Lock the Login Keychain (Optional)

* Open Keychain Access and select the login Keychain
* Choose Edit → Change Settings for Keychain "Login"
* Set Lock after [...] minutes of inactivity to 10
* Check "Lock when sleeping"

Note: Locking the keychain automatically can impact the user experience. Since on every lock daemons such as the wifi service requires an unlock. Hence, automatic nightly backups over wifi will be affected.

---

# General Configuration

## Patching the current system (Mandatory)

It is highly recommended to lift the current system state to a fully up-to date and patched system before performing the described hardening measures in this document. 
It is possible to check the current system for updates through either the AppStore with:
Apple menu → App Store → Updates

Or issuing the following command on the command line:

```
$ softwareupdate -l 
```
---

## Auto Updates (Mandatory)

It is recommended to always have auto updates enabled to deliver latest security and software patches automatically to the system. The following command checks whether this setting is enabled or not:

```
$ defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates
1
```
If automatic updates are enabled, the return value should be 1 as displayed in the output. If the setting is not present, it can be manually set using the following command:
```
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -int 1
```
---
## Gatekeeper (Mandatory)

Gatekeeper will check if the Application is signed with a valid Apple Certificate. Checking Applications for the Signature is possible with:
```
spctl –a /Applications/test.app
```
If you want to add it to Gatekeeper you can use:
```
spctl --add test.app
```
or simply:
* right click → open
Note: Sometimes it will still deny opening the Application. You can then force the start:
* System Preferences → Security & Privacy → General
* Open "Application"

---

## Enforcing Code Signing (Mandatory)

Edit the following line in ```/etc/sysctl.conf:```
```
vm.cs_force_kill=1  # Kill process if invalidated
vm.cs_force_hard=1  # Fail operation if invalidated
vm.cs_all_vnodes=1  # Apply on all Vnodes
vm.cs_enforcement=1 # Globally apply code signing enforcement
```
Note: This change will require to disable System Integrity Protection (Remember to Enable it after Hardening). On a fresh installed system it is possible that ```sysctl.conf``` is not existent. If so, you can create it and reboot the system. 

---

## Disable Creation of Metadata Files (Mandatory)

It is recommended to prohibit Mac OS from creating temporary files on remote volumes such as network storage or USB storage. The following commands will prevent this behavior:
```
defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true
defaults write com.apple.desktopservices DSDontWriteUSBStores -bool true
```

---

## Disable saving to iCloud (Mandatory)

The following command prevent Mac OS from saving files directly to any iCloud server:

```
sudo defaults write NSGlobalDomain NSDocumentSaveNewDocumentsToCloud -bool false
```

---

## Disable Diagnostics (Mandatory)

To avoid sending data to Apple or App Developers, disable the following:

* System Preferences → Security & Privacy → Privacy → Diagnostics & Usage
* Uncheck “Send diagnostic & usage data to Apple”
* Uncheck “Share crash data with app developers”

---

## Disable Handoff (Mandatory)

Apples Handoff is a feature to keep your workspaces in sync but it does require to send data to Apple which is recommended to be disabled.

* System Preferences → General
* Uncheck “Allow Handoff between this Mac and your iCloud devices”
* Set “Recent Items” to none. You will find this inside of the dropdown box right above the Handoff option

---

## FileVault (Mandatory)

It is recommended to enable FileVault to use full disk encryption on your device. It should be already enabled by default. However, turning on FileVault after installing macOS is more secure because of a "better" (more random) seed from the (Pseudo Random Number Generator)

* System Preferences → Security & Privacy → FileVault
* Enable FileVault

Optional:

To remove the encryption key from memory and remove power from memory when hibernating, issue the following command:

```
sudo pmset -a destroyfvkeyonstandby 1 hibernatemode 25
```

Note: This might have an impact to the user experience since the disk has to be decrypted on every lid open. This can take up to 10 additional seconds for booting.
In case of a highly secured MacBook with destroying the FileVault key on standby other power settings can be applied to safe energy (Usually the MacBook wakes up and checks different things like Backup etc. However, when destroying the FileVault key on standby it cannot perform these operations). The preferred settings in this mode are the following:

```
sudo pmset -a powernap 0
sudo pmset -a standby 0
sudo pmset -a standbydelay 0
sudo pmset -a autopoweroff 0
````

---

## Firewall (Mandatory)

It is recommended to enable the Firewall with full functionality and block all incoming traffic.

* System Preferences → Security & Privacy → Firewall
* Click on "Turn on Firewall"
* Click on "Firewall options"
* Set "Block all incoming connections"
* Set “Enable stealth mode”

---

## Require Administrator Password (Mandatory)

It is recommended to always require the administrator password to access system settings.

---

## Screensaver and Un-locking (Mandatory)

It is recommended to automatically lock your screen when inactive.

* System Preferences → Desktop & Screensaver → Screensaver
* Adjust the timeframe to your needs but we recommend setting it to 5 minutes.
* System Preferences → Security & Privacy → General
* Set "Require password immediately after sleep or screen saver begins"

---

## Filename Extensions (Mandatory)

To be always clear what sort of file you´re processing, it is recommended to turn on displaying Filename extensions.
* Open Finder → Settings → Advanced
* Set "Show all filename extensions"

---

## Prevent Safari from Opening Known File Types (Mandatory)

If you are using Safari as your main Browser, it is recommended to prevent Safari from opening known files after downloading.

* Open Safari → Preferences → General
* Unset "Open safe files after downloading"

---

## Set Strict Global Umask (Optional)

The Strict Global Umask defaults the Permission of any File or Directory that is created by a user in the future. You can adjust the Global Umask with the following command:

```
sudo launchctl config system umask 027
```

Note: This might break the installation of additional Software that relies on a less restrict umask.

---

## Disable Remote Apple Events (Mandatory)

It is recommended to disable (Default) the Remote Apple Event service. This service can be used to perform operations on software over the network to another Mac. Hence, it should be always disabled. The following command line checks whether Remote Apple Events is enabled or not:

```
sudo systemsetup -getremoteappleevents
```
Ensure that the output is:
```
Remote Apple Events: Off
```
If it is enabled the following command will disable it:
```
sudo systemsetup -setremoteappleevents off
```

---

# Technical Configuration

## Disable Bluetooth (Optional)

It is recommended to disable Bluetooth while it is not used. This is recommended due to some security concerns in the past with attacks against the Bluetooth pairing and identity detection. 

* System Preferences → Bluetooth
* Deactivate Bluetooth

Note: Deactivating Bluetooth will prevent any peripherals like a Bluetooth keyboard/mouse or headset from connecting. 

---

## Firmware Password (Mandatory)

To prevent Single User Mode and bootable devices, it is recommended to set a sufficient complex Firmware Password.

* Boot your Mac into Recovery Mode by pressing Command + R as your Mac is booting.
* Select Utilities → Firmware Password Utility
* Set a sufficient complex Password

Note: Forgetting this password can render the Mac completely unavailable and prevent it from booting. Hence, a password manager storing this password can be a solution. Further, when trying to access a firmware secured part regardless of the real keyboard layout of the MacBook the English default setting will always be mapped. 

---

## Setuid and Setgid (Optional)

Altering the Setuid bits of binaries can be an important step. This may affect or break functionality on these binaries but you can always reverse these Steps. Use the following Command to get a list of all SUID binaries:

```
sudo find / -perm -04000 -ls
sudo find / -perm -02000 -ls
```
Filter out Applications where you suspect “Bad code quality” or you generally don´t trust (E.G. peripheral device driver of your mouse).
The following commands unset the described permissions on files and directories:

```
chmod u-s #file
chmod g-s #file
```

---

## Disable Core Dumps (Mandatory)

To limit Kernel Information leaks, disable the core dumping capability. Edit the following line in ```/etc/sysctl.conf:```

```
kern.coredump=0
```

Note: This change will require to disable System Integrity Protection (Remember to Enable it after Hardening). On a freshly installed system it is possible that ```sysctl.conf``` is not existent. If so you can create it and reboot the system. 

Since Kerneldumps can be helpful for debugging you can enable it temporarily with:

```
sudo sysctl -w kern.coredump=1
```
---

## Disabling USB/Bluetooth and other mass storage peripherals (Optional)

In some cases it is needed to disable inserting any mass storage to the system. This can be achieved either by deleting the KEXT driver or using enterprise MDM tools to deny such usages.

To completely disable USB Mass storage it is possible to delete the KEXT driver ```IOUSBMassStorageClass.kext``` in ```/System/Library/Extensions``` (SIP has to be disabled). It is also possible to completely disable Bluetooth by deleting ```IOBlueToothFamily``` in the previous mentioned folder. After deleting the kext drivers, it is needed to perform the following command on the directory to rebuild the kernelcache:

```
touch /System/Library/Extensions
```

Note: This can affect usability of the MacBook due to no mass storage can be inserted. However, USB Keyboards will still work. On a major version update, this might be reverted again and it can be possible to use USB again (keep in mind to check this hardening measure after a major Mac OS update).

Further, some commercial software (https://www.endpointprotector.com/products/endpoint-protector) can perform similar port blocking but have not been tested by the author yet. 

---

# Network and Communication Security

## Advanced Firewall (Optional)

It is recommended to monitor more precise on Application Traffic. Software Firewalls can generate their own rulesets for different Locations and Networks.
We can recommend a more Advanced Firewall like “Little Snitch”, “Radio Silence” and “Handoff” which are full blown local Firewall (25-35€). If you are looking for a free alternative you can look at the lite version of “Murus”.

* https://www.obdev.at/products/littlesnitch/index-de.html
* https://www.oneperiodic.com/products/handsoff/
* https://radiosilenceapp.com/
* http://www.murusfirewall.com/

---

## Disable Wake on Lan (Mandatory)

* System Preferences → Energy Saver
* Unset "Wake for network access"

---

## Disable Apple File Protocol (AFP) (Mandatory)

Apples equivalent to SMB. It is disabled by default on OS X 10.11. You can verify this under:

* System Preferences → Sharing
* Select "File Sharing" → Options
* Unset "Share Files and folders using AFP"

Note: It is also possible to disable this via the Command-Line:

```
sudo launchctl unload -w /System/Library/LaunchAgents/AppleFileServer.plist
```

---

## Disable Unnecessary Services (Optional)

you can disable unnecessary services by issuing the following command:

```
sudo launchctl unload -w /System/Library/LaunchAgents/<Service
```

Note: This can break functionality on the System. To load them back up just replace “unload” with “load”.

We attached a List of Services that may be unnecessary for your installation at the end of the OS Hardening Section.

More Services (```Plistfiles````) can be Found in the following directories:

* /System/Library/LaunchDaemons
* /System/Library/LaunchAgents
* /Library/LaunchDaemons
* /Library/LaunchAgents
* /Users/<USERNAME>/Library/LaunchDaemons
* /Users/<USERNAME>/Library/LaunchAgents

---

## Disable Sharing (Mandatory)

Sharing is disabled on default. You can verify this here:

* System Preferences → Sharing
* Unset everything which is not needed

---

## Enable Network Time Synchronization via NTP (Mandatory)

To ensure that your clock is always correct and not corrupted (e.g. important for Log-Files), use the following Commands:

```
sudo systemsetup -setnetworktimeserver "time.euro.apple.com"
sudo systemsetup -setusingnetworktime on 
echo "restrict default ignore" >> /etc/ntp.conf
```

---

# Privacy

The following chapter will describe measures to increase the privacy.

---

## Computer-/Hostname (Mandatory)

It is recommended to mask the name of the host since it can comprise the user name and the current operating system (MacBook → Mac OS). Therefore the following command can be issued to change the name which is displayed over the network:

```
sudo scutil --set ComputerName ExampleName
sudo scutil --set LocalHostName ExampleName
````

## Limit Ad Tracking (Mandatory)

To limit tracking of the device disable the following:

* System Preferences → Security & Privacy → Privacy → Advertising
* Check “Limit Ad Tracking”

---

## Tracking Services (Mandatory)

It is recommended to disable the Tracking Services. If you decide to use the Tracking Services, it is possible to disable it just for the Spotlight Suggestions.

* *System Preferences → Security & Privacy → Privacy → Location Services
* Select "System Services" → Details
* Uncheck "Spotlight Suggestions"

---

# Appendix List of Services

The following table lists service files and the corresponding functionality that should be disabled/must not be enabled unless required.

Example for table:

| | |
| ------------- |:-------------:|
|  com.apple.AppleFileServer.plist | AFP |
| ftp.plist | FTP |
| org.apache.httpd.plist | HTTP Server |
|  epcc.plist | Remote Apple Events |
| com.apple.xgridagentd.plist | Xgrid |
| com.apple.xgridcontrollerd.plist | Xgrid |
| com.apple.InternetSharing.plist | Iternet Sharing |
| com.apple.dashboard.advisory.fetch.plist | Dashboard Auto-Update |
| com.apple.UserNotificationCenter.plist | User notifications |
|  com.apple.RemoteDesktop.PrivilegeProxy.plist| ARD |
|  com.apple.RemoteDesktop.plist | ARD |
|  com.apple.IIDCAssistant.plist | iSight |
|  com.apple.blued.plist | Bluetooth |
|  com.apple.RemoteUI.plist | Remote Control |
|  com.apple.gamed.plist | Game Center |
| | |