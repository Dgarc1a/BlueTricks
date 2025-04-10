## Configuration Assessment

Security scripts and best practices for hardening Linux servers. Contributions are welcome to help us grow together! 🔐💪❤️


### Updates and basic maintenance
 
<pre>
sudo apt update && sudo apt upgrade -y
sudo apt install unattended-upgrades apt-listchanges -y
sudo dpkg-reconfigure --priority=low unattended-upgrades
</pre>

### Account and privilege management

- Remove unnecessary users:
<pre>getent passwd | grep -vE '/nologin|/false'</pre>

### Ensure password reuse is limited
	
- File: /etc/pam.d/common-password

- Rationale: Forcing users not to reuse their past 5 passwords make it less likely that an attacker will be able to guess the password.
- Remediation:

⚠️ Pay special attention to the configuration. Incorrect configuration can cause system lock outs. This is example configuration. You configuration may differ based on previous changes to the files.
Edit the /etc/pam.d/common-password file to include the remember option and conform to site policy as shown:

<pre>password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt remember=5</pre>

### Ensure access to the su command is restricted
	
File: /etc/pam.d/su
	
- Rationale: Restricting the use of su , and using sudo in its place, provides system administrators better control of the escalation of user privileges to execute privileged commands. The sudo utility also provides a better logging and audit mechanism, as it can log each command executed via sudo , whereas su can only record that a user executed the su program.
- Remediation: Create an empty group that will be specified for use of the su command. The group should be named according to site policy.

- Example:
<pre>sudo groupadd sugroup</pre>

- Add the following line to the /etc/pam.d/su file, specifying the empty group:
<pre> auth required pam_wheel.so use_uid group=sugroup</pre>

### Ensure ntp is enabled and running
	
- Rationale: ntp needs to be enabled and running in order to synchronize the system to a timeserver. Time synchronization is important to support time sensitive security mechanisms and to ensure log files have consistent time records across the enterprise to aid in forensic investigations.
- Remediation: IF ntp is in use on the system, Run the following command to unmask ntp.service:
 
<pre>sudo systemctl unmask ntp.service </pre> 
- Run the following command to enable and start ntp.service
<pre>sudo systemctl --now enable ntp.service </pre>
  
- OR If another time synchronization service is in use on the system, run the following command to remove ntp 
<pre>sudo apt purge ntp</pre>  


### Ensure authentication required for single user mode

- Rationale
    Requiring authentication in single user mode prevents an unauthorized user from rebooting the system into single user to gain root privileges without credentials.
- Remediation
    Run the following command and follow the prompts to set a password for the root user:
     
<pre>passwd root</pre>
	
### Ensure DHCP Server is not installed
	
- Rationale: Unless a system is specifically set up to act as a DHCP server, it is recommended that this package be removed to reduce the potential attack surface.
- Remediation: Run the following command to remove isc-dhcp-server: 
<pre>sudo apt purge isc-dhcp-server</pre>
    
### Ensure password hashing algorithm is up to date with the latest standards
	
- File: /etc/pam.d/common-password
	
- Rationale: The yescrypt algorithm provides much stronger hashing than previous available algorithms, thus providing additional protection to the system by increasing the level of effort for an attacker to successfully determine passwords. Note: these change only apply to accounts configured on the local system.
- Remediation:
⚠️ Pay special attention to the configuration. Incorrect configuration can cause system lock outs. This is example configuration. You configuration may differ based on previous changes to the files. PAM Edit the /etc/pam.d/common-password file and ensure that no hashing algorithm option for pam_unix.so is set: 
<pre>password try_first_pass remember=5 [success=1 default=ignore] pam_unix.so obscure use_authtok Login definitions </pre>

Edit /etc/login.defs and ensure that ENCRYPT_METHOD is set to yescrypt.    

### Unnecessary services

<pre>systemctl list-units --type=service --state=running</pre>

- Disable what you don't need

<pre>
 sudo systemctl disable <service name>
 sudo systemctl stop   <service name>
</pre>

### Kernel and sysctl security

- File: /etc/sysctl.conf
<pre>
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv6.conf.all.disable_ipv6 = 1   # Se não usar IPv6
kernel.kptr_restrict = 2
</pre>
- Apply
<pre>sudo sysctl -p</pre>

### Ensure LDAP client is not installed
	
Command:
<pre>dpkg-query -s ldap-utils</pre>
	
- Rationale: If the system will not need to act as an LDAP client, it is recommended that the software be removed to reduce the potential attack surface.
- Remediation: Uninstall ldap-utils
<pre>apt purge ldap-utils</pre>

### Ensure LDAP server is not installed
	
Command:
<pre>dpkg-query -s slapd</pre>
	
- Rationale: If the system will not need to act as an LDAP server, it is recommended that the software be removed to reduce the potential attack surface.
- Remediation: Run one of the following commands to remove slapd
<pre>apt purge slapd</pre>


## Security Tools 

### Ensure AppArmor is enabled in the bootloader configuration
- Rationale: AppArmor must be enabled at boot time in your bootloader configuration to ensure that the controls it provides are not overridden.
- Remediation: Edit /etc/default/grub and add the apparmor=1 and security=apparmor parameters to the GRUB_CMDLINE_LINUX= line GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor" 
Run the following command to update the grub2 configuration:
- Apply 
<pre>update-grub</pre>

### Ensure all AppArmor Profiles are enforcing

- Rationale: Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that any policies that exist on the system are activated.
- Remediation: Run the following command to set all profiles to enforce mode: 
<pre>aa-enforce /etc/apparmor.d/*</pre>    
⚠️ Any unconfined processes may need to have a profile created or activated for them and then be restarted.

### Firewall UFW configuration 
- install and basic config
<pre>
sudo apt install ufw -y
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 2222/tcp   # Custom SSH
sudo ufw enable
</pre>

### Fail2Ban for brute-force mitigation
- install and start
<pre>
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
</pre>

- Create local configuration

<pre>
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo nano /etc/fail2ban/jail.local
</pre>

- Example:
<pre>
[sshd]
enabled = true
port = 2222
filter = sshd
maxretry = 3
bantime = 1h
</pre>
	

### Hardening ssh
### Ensure permissions on /etc/ssh/sshd_config are configured
	
- Command: 
<pre>stat /etc/ssh/sshd_config</pre>
	
- Rationale: The /etc/ssh/sshd_config file needs to be protected from unauthorized changes by non-privileged users.
- Remediation: Run the following commands to set ownership and permissions on /etc/ssh/sshd_config:
<pre>     
sudo chown root:root /etc/ssh/sshd_config 
sudo chmod og-rwx /etc/ssh/sshd_config
</pre>    

<pre>sudo nano /etc/ssh/sshd_config</pre>

- Examples:
<pre>
Port 2222                    # Custom port
Protocol 2
PermitRootLogin no
PasswordAuthentication no    # Enable only if password is used
PermitEmptyPasswords no
AllowUsers <usernames>
ClientAliveInterval 15
ClientAliveCountMax 3
</pre>

apply:
<pre>sudo systemctl restart ssh</pre>

⚠️ Make sure your public key is in ~/.ssh/authorized_keys before turning off password authentication.

### Ensure SSH AllowTcpForwarding is disabled
	
Command: 
<pre>sshd -T</pre>
	
- Rationale: Leaving port forwarding enabled can expose the organization to security risks and backdoors. SSH connections are protected with strong encryption. This makes their contents invisible to most deployed network monitoring and traffic filtering solutions. This invisibility carries considerable risk potential if it is used for malicious purposes such as data exfiltration. Cybercriminals or malware could exploit SSH to hide their unauthorized communications, or to exfiltrate stolen data from the target network.
- Remediation: Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
<pre>AllowTcpForwarding no</pre>

### Ensure SSH warning banner is configured
	
Command: 
<pre>sshd -T</pre>
	
- Rationale: Banners are used to warn connecting users of the particular site's policy regarding connection. Presenting a warning message prior to the normal user login may assist the prosecution of trespassers on the computer system.
- Remediation: Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
<pre>Banner /etc/issue.net</pre>
 
### Ensure SSH MaxAuthTries is set to 4 or less
	
<pre>sshd -T</pre>

- Rationale: Setting the MaxAuthTries parameter to a low number will minimize the risk of successful brute force attacks to the SSH server. While the recommended setting is 4, set the number based on site policy.
- Remediation: Edit the /etc/ssh/sshd_config file to set the parameter as follows: 
<pre>MaxAuthTries 3</pre> 

### Ensure SSH MaxStartups is configured
	
Command:
<pre>sshd -T</pre>
	
- Rationale: To protect a system from denial of service due to a large number of pending authentication connection attempts, use the rate limiting function of MaxStartups to protect availability of sshd logins and prevent overwhelming the daemon.
- Remediation: Edit the /etc/ssh/sshd_config file to set the parameter as follows:
    
<pre>MaxStartups 10:30:60</pre>   
    
### Ensure SSH LoginGraceTime is set to one minute or less
	
Command:
<pre>sshd -T</pre>
	
- Rationale: Setting the LoginGraceTime parameter to a low number will minimize the risk of successful brute force attacks to the SSH server. It will also limit the number of concurrent unauthenticated connections. While the recommended setting is 60 seconds (1 Minute), set the number based on site policy.
- Remediation: Edit the /etc/ssh/sshd_config file to set the parameter as follows:
    
<pre>LoginGraceTime 60</pre>  
     

## Audit and logs

- install and apply
<pre> 
sudo apt install auditd audispd-plugins -y
sudo systemctl enable auditd
sudo systemctl start auditd
sudo ausearch -x /bin/su
</pre>

### Ensure audit tools are 755 or more restrictive
	
Command: 
<pre>stat -c "%n %a" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules</pre>
	
- Rationale: Protecting audit information includes identifying and protecting the tools used to view and manipulate log data. Protecting audit tools is necessary to prevent unauthorized operation on audit information.
- Remediation: Run the following command to remove more permissive mode from the audit tools:
<pre>chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules</pre>

### Ensure audit tools are owned by root
	
Command: 
<pre>stat -c "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules</pre>	

- Rationale: Protecting audit information includes identifying and protecting the tools used to view and manipulate log data. Protecting audit tools is necessary to prevent unauthorized operation on audit information.
- Remediation: Run the following command to change the owner of the audit tools to the root user: 
<pre>chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules</pre>

### Monitoring and integrity

- install 

<pre>
sudo apt install aide -y
sudo aideinit
</pre>


## Optional

#### Automatic checks

- install
<pre>
sudo apt install lynis -y
sudo lynis audit system
</pre> 


- 🔭 I’m currently working on it ...
- 🌱 I’m currently learning more about it ...
- 👯 I’m looking to collaborate on ...

