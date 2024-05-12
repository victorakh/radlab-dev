#!/bin/bash

# Copyright 2023 Google LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Create dir for sample notebooks
echo "Creating directory to store samples."
mkdir -p /home/jupyter/sample/notebooks

# Setting environment variabled for Project ID
echo "Setting Project ID variable."
export PROJECT_ID=$(gcloud config get-value project)

# Copy samples to the notebook
echo "Copying sample notebooks to the instance."
gsutil -m cp -r gs://user-scripts-${PROJECT_ID}/notebooks/*.ipynb /home/jupyter/sample/notebooks

echo "Startup script finished."

#auto-shutdown script - enable if needed

# wget https://raw.githubusercontent.com/GoogleCloudPlatform/ai-platform-samples/master/notebooks/tools/auto-shutdown/install.sh
# wget https://raw.githubusercontent.com/GoogleCloudPlatform/ai-platform-samples/master/notebooks/tools/auto-shutdown/ashutdown.service
# wget https://raw.githubusercontent.com/GoogleCloudPlatform/ai-platform-samples/master/notebooks/tools/auto-shutdown/ashutdown

# ./install.sh









##########################  OS Hardening Script Starts Here  #################################  

# Define the output file with date
OUTPUT_FILE="/home/jupyter/os-hardening-output-$(date +%F).txt"

# Redirect all output to a file
exec > "$OUTPUT_FILE" 2>&1

# Ensure the script is run as root or sudo privileges 
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root. Re-invoking with sudo..."
  sudo "$0" "$@"  # Re-run the current script as root
  exit $?
fi

# Function to check if a package is installed
check_package_installed() {
    if dpkg-query -W -f='${Status}' $1 2>/dev/null | grep -q "ok installed"; then
        return 0
    else
        return 1
    fi
}



# No Interactive installation
export DEBIAN_FRONTEND=noninteractive


# Function to install a package
install_package() {
    echo "Installing $1..."
    apt-get update && apt-get install -y $1
    if [ $? -eq 0 ]; then
        echo "$1 installed successfully."
    else
        echo "Failed to install $1."
        exit 1
    fi
}


# Install Google Cloud Ops Agent for monitoring
echo "Installing Google Cloud Ops Agent for monitoring - STARTING" 
curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
sudo bash add-google-cloud-ops-agent-repo.sh --also-install
echo "Installing Google Cloud Ops Agent for monitoring - COMPLETED" 


#1.3.1 Ensure AIDE is installed - aide 
#1.3.1 Ensure AIDE is installed - aide-common

echo "1.3.1 Ensure AIDE is installed - aide - STARTING"
echo "1.3.1 Ensure AIDE is installed - aide-common - STARTING"

apt-get update
apt-get install -y aide aide-common

echo "1.3.1 Ensure AIDE is installed - aide - COMPLETED"
echo "1.3.1 Ensure AIDE is installed - aide-common - COMPLETED"


#echo "Configuring AIDE..."
# Note: Configuration specifics should be added here based on environment requirements
# For example, you might want to modify the /etc/aide/aide.conf file here
# cp /etc/aide/aide.conf /etc/aide/aide.conf.backup
# echo "ADD YOUR CONFIGURATION OPTIONS HERE IF REQUIRED" >> /etc/aide/aide.conf

#echo "Initializing AIDE, this might take a while..."
#yes | aideinit


# Check if aideinit was successful
#if [ -f /var/lib/aide/aide.db.new ]; then
#    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
#    echo "AIDE initialization complete and database moved successfully."
#else
#    echo "Failed to create AIDE database. Check for errors above."
#fi



# 1.3.2 Ensure filesystem integrity is regularly checked
echo "1.3.2 Ensure filesystem integrity is regularly checked - STARTING"
echo "0 5 * * * /usr/bin/aide --check" > /etc/cron.d/aide-check
echo "1.3.2 Ensure filesystem integrity is regularly checked - COMPLETED"



# 1.9 Ensure updates, patches, and additional security software are installed
echo "1.9 Ensure updates, patches, and additional security software are installed - STARTING"
apt-get update && apt-get upgrade -y
apt-get dist-upgrade -y
echo "0 3 * * * root apt-get update && apt-get upgrade -y && apt-get autoremove -y" > /etc/cron.d/auto-updates
systemctl daemon-reload
echo "1.9 Ensure updates, patches, and additional security software are installed - COMPLETED"


# 5.5.1.4 Ensure inactive password lock is 30 days or less - useradd
echo "5.5.1.4 Ensure inactive password lock is 30 days or less - useradd - STARTING"
useradd -D -f 30
echo "5.5.1.4 Ensure inactive password lock is 30 days or less - useradd - COMPLETED"



# 5.5.1.4 Ensure inactive password lock is 30 days or less - users
echo "5.5.1.4 Ensure inactive password lock is 30 days or less - users - STARTING"
awk -F: '($2 != "!" && $2 != "*" && $1 != "root") {print $1}' /etc/shadow | while read -r user
do
    chage --inactive 30 "$user"
done
echo "5.5.1.4 Ensure inactive password lock is 30 days or less - users - COMPLETED"



#5.1.2 Ensure permissions on /etc/crontab are configured 
#5.1.3 Ensure permissions on /etc/cron.hourly are configured
#5.1.4 Ensure permissions on /etc/cron.daily are configured 
#5.1.5 Ensure permissions on /etc/cron.weekly are configured
#5.1.6 Ensure permissions on /etc/cron.monthly are configured
#5.1.7 Ensure permissions on /etc/cron.d are configured

echo "#5.1.2 Ensure permissions on /etc/crontab are configured - STARTING"
echo "#5.1.3 Ensure permissions on /etc/cron.hourly are configured - STARTING"
echo "#5.1.4 Ensure permissions on /etc/cron.daily are configured - STARTING" 
echo "#5.1.5 Ensure permissions on /etc/cron.weekly are configured - STARTING"
echo "#5.1.6 Ensure permissions on /etc/cron.monthly are configured - STARTING"
echo "#5.1.7 Ensure permissions on /etc/cron.d are configured - STARTING"


# Define a function to set permissions and ownership
set_cron_permissions() {
    local path=$1
    echo "Setting permissions for $path"
    
    # Change ownership to root user and root group
    chown root:root $path
    
    # Set file permissions to 600 (read/write for owner, none for others)
    chmod 600 $path
    
    # Check the result
    if [ $? -eq 0 ]; then
        echo "Permissions set successfully for $path"
    else
        echo "Failed to set permissions for $path"
    fi
}

# Main execution
# Ensure permissions on /etc/crontab
set_cron_permissions "/etc/crontab"

# Ensure permissions on /etc/cron.hourly
set_cron_permissions "/etc/cron.hourly"

# Ensure permissions on /etc/cron.daily
set_cron_permissions "/etc/cron.daily"

# Ensure permissions on /etc/cron.weekly
set_cron_permissions "/etc/cron.weekly"

# Ensure permissions on /etc/cron.monthly
set_cron_permissions "/etc/cron.monthly"

# Ensure permissions on /etc/cron.d
set_cron_permissions "/etc/cron.d"

echo "Cron hardening script executed."


echo "#5.1.2 Ensure permissions on /etc/crontab are configured - COMPLETED"
echo "#5.1.3 Ensure permissions on /etc/cron.hourly are configured - COMPLETED"
echo "#5.1.4 Ensure permissions on /etc/cron.daily are configured - COMPLETED" 
echo "#5.1.5 Ensure permissions on /etc/cron.weekly are configured - COMPLETED"
echo "#5.1.6 Ensure permissions on /etc/cron.monthly are configured - COMPLETED"
echo "#5.1.7 Ensure permissions on /etc/cron.d are configured - COMPLETED"


# 1.5.4 Ensure core dumps are restricted - limits config
echo "1.5.4 Ensure core dumps are restricted - limits config - STARTING"

cat << EOF >> /etc/security/limits.conf
* hard core 0
EOF
echo "1.5.4 Ensure core dumps are restricted - limits config - COMPLETED"



# 1.5.4 Ensure core dumps are restricted - sysctl config
echo "1.5.4 Ensure core dumps are restricted - sysctl config - STARTING"

cat << EOF >> /etc/sysctl.conf
# Set kernel parameters to prevent core dumps
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
EOF

# Reload sysctl configuration
sysctl -p
echo "1.5.4 Ensure core dumps are restricted - sysctl config - COMPLETED"


# Define the security warning banner
SECURITY_BANNER="Authorized uses only. All activity may be monitored and reported.> /etc/issue.net"


# 1.7.1 Ensure message of the day is configured properly - banner
echo "1.7.1 Ensure message of the day is configured properly - banner - STARTING"

# Define the security warning banner
SECURITY_BANNER="Authorized uses only. All activity may be monitored and reported.> /etc/issue.net"

echo "$SECURITY_BANNER" > /etc/motd
echo "1.7.1 Ensure message of the day is configured properly - banner - COMPLETED"



# 1.7.2 Ensure local login warning banner is configured properly - banner
echo "1.7.2 Ensure local login warning banner is configured properly - banner - STARTING"
echo "$SECURITY_BANNER" > /etc/issue
echo "1.7.2 Ensure local login warning banner is configured properly - banner - COMPLETED"

# 1.7.3 Ensure remote login warning banner is configured properly - banner
echo "1.7.3 Ensure remote login warning banner is configured properly - banner - STARTING"
echo "$SECURITY_BANNER" > /etc/issue.net
echo "1.7.3 Ensure remote login warning banner is configured properly - banner - COMPLETED"



#3.2.2 Ensure IP forwarding is disabled - sysctl ipv4 
# File for sysctl configuration
SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"

# Start configuration
echo "# Hardening network settings" > "$SYSCTL_CONF"

#3.2.2 Ensure IP forwarding is disabled"
echo "3.2.2 Ensure IP forwarding is disabled - STARTING"
echo "net.ipv4.ip_forward = 0" >> "$SYSCTL_CONF"
echo "net.ipv6.conf.all.forwarding = 0" >> "$SYSCTL_CONF"
echo "3.2.2 Ensure IP forwarding is disabled - COMPLETED"

#3.3.1 Ensure source routed packets are not accepted - IPv6
echo "3.3.1 Ensure source routed packets are not accepted - STARTING"
echo "net.ipv6.conf.all.accept_source_route = 0" >> "$SYSCTL_CONF"
echo "net.ipv6.conf.default.accept_source_route = 0" >> "$SYSCTL_CONF"
echo "3.3.1 Ensure source routed packets are not accepted - COMPLETED"

#3.3.2 Ensure ICMP redirects are not accepted - IPv6
echo "3.3.2 Ensure ICMP redirects are not accepted - IPv6 - STARTING"
echo "net.ipv6.conf.all.accept_redirects = 0" >> "$SYSCTL_CONF"
echo "net.ipv6.conf.default.accept_redirects = 0" >> "$SYSCTL_CONF"
echo "3.3.2 Ensure ICMP redirects are not accepted - IPv6 - COMPLETED"

#3.3.3 Ensure secure ICMP redirects are not accepted - IPV4
echo "3.3.3 Ensure secure ICMP redirects are not accepted - IPV4 - STARTING"
echo "net.ipv4.conf.all.secure_redirects = 0" >> "$SYSCTL_CONF"
echo "net.ipv4.conf.default.secure_redirects = 0" >> "$SYSCTL_CONF"
echo "3.3.3 Ensure secure ICMP redirects are not accepted - IPV4 - COMPLETED"

#3.3.9 Ensure IPv6 router advertisements are not accepted
echo "3.3.9 Ensure IPv6 router advertisements are not accepted - STARTING"
echo "net.ipv6.conf.all.accept_ra = 0" >> "$SYSCTL_CONF"
echo "net.ipv6.conf.default.accept_ra = 0" >> "$SYSCTL_CONF"

# Apply all sysctl settings
sysctl --system
echo "3.3.9 Ensure IPv6 router advertisements are not accepted - COMPLETED"


# 5.1.8 Ensure cron is restricted to authorized users - '/etc/cron.allow'
echo "5.1.8 Ensure cron is restricted to authorized users - '/etc/cron.allow - STARTING"
echo "root" > /etc/cron.allow
chmod 600 /etc/cron.allow
echo "5.1.8 Ensure cron is restricted to authorized users - '/etc/cron.allow - COMPLETED"


# 5.1.9 Ensure at is restricted to authorized users - '/etc/at.allow'
echo "5.1.9 Ensure at is restricted to authorized users - '/etc/at.allow' - STARTING"
echo "root" > /etc/at.allow
chmod 600 /etc/at.allow
echo "5.1.9 Ensure at is restricted to authorized users - '/etc/at.allow' - COMPLETED"


# 5.4.3 Ensure password reuse is limited
echo "5.4.3 Ensure password reuse is limited - STARTING"
sed -i '/^password\s*requisite\s*pam_pwhistory.so/ s/$/ remember=5/' /etc/pam.d/common-password
echo "5.4.3 Ensure password reuse is limited - COMPLETED"


# 5.5.1.1 Ensure minimum days between password changes is configured - login.defs
echo "5.5.1.1 Ensure minimum days between password changes is configured - login.defs - STARTING"
sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   7' /etc/login.defs
echo "5.5.1.1 Ensure minimum days between password changes is configured - login.defs - COMPLETED"

# 5.5.1.1 Ensure minimum days between password changes is configured - users
echo "5.5.1.1 Ensure minimum days between password changes is configured - users - STARTING"
getent passwd | cut -d: -f1 | while read user; do
    chage --mindays 7 "$user"
done
echo "5.5.1.1 Ensure minimum days between password changes is configured - users - COMPLETED"


# 5.5.1.2 Ensure password expiration is 365 days or less - login.defs
echo "5.5.1.2 Ensure password expiration is 365 days or less - login.defs - STARTING"
sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   365' /etc/login.defs
echo "5.5.1.2 Ensure password expiration is 365 days or less - login.defs - COMPLETED"


# 5.5.1.2 Ensure password expiration is 365 days or less - users
echo "5.5.1.2 Ensure password expiration is 365 days or less - users - STARTING"
getent passwd | cut -d: -f1 | while read user; do
    chage --maxdays 365 "$user"
done
echo "5.5.1.2 Ensure password expiration is 365 days or less - users - COMPLETED"


# 5.5.4 Ensure default user umask is 027 or more restrictive - Default user umask
echo "5.5.4 Ensure default user umask is 027 or more restrictive - Default user umask - STARTING"
sed -i '/^UMASK/ c\UMASK           027' /etc/login.defs
echo "5.5.4 Ensure default user umask is 027 or more restrictive - Default user umask - COMPLETED"


# 5.5.4 Ensure default user umask is 027 or more restrictive - Restrictive system umask
echo "5.5.4 Ensure default user umask is 027 or more restrictive - Restrictive system umask - STARTING"
echo "umask 027" > /etc/profile.d/umask.sh
echo "5.5.4 Ensure default user umask is 027 or more restrictive - Restrictive system umask - COMPLETED"



# 1.1.10 Disable USB Storage - modprobe and blacklist
echo "1.1.10 Disable USB Storage - modprobe and blacklist - STARTING"
echo "install usb-storage /bin/true" > /etc/modprobe.d/usb-storage.conf
echo "blacklist usb-storage" >> /etc/modprobe.d/usb-storage.conf
echo "1.1.10 Disable USB Storage - modprobe and blacklist - COMPLETED"


# 1.4.1 Ensure bootloader password is set - 'set superusers' and 'passwd_pbkdf2'
echo "1.4.1 Ensure bootloader password is set - 'set superusers' and 'passwd_pbkdf2' - STARTING"
# Define the bootloader password
PASSWORD='BLP@ssw0rd'

# Generate the PBKDF2 hash
HASH=$(echo -e "$PASSWORD\n$PASSWORD" | grub-mkpasswd-pbkdf2 | awk '/PBKDF2 hash of your password is/{print $NF}')


echo "Setting bootloader password..."
echo 'set superusers="admin"' > /etc/grub.d/40_custom
echo "password_pbkdf2 admin $HASH" >> /etc/grub.d/40_custom
update-grub
echo "1.4.1 Ensure bootloader password is set - 'set superusers' and 'passwd_pbkdf2' - COMPLETED"


# 1.4.2 Ensure permissions on bootloader config are configured
echo "1.4.2 Ensure permissions on bootloader config are configured - STARTING"
chmod 600 /boot/grub/grub.cfg
echo "1.4.2 Ensure permissions on bootloader config are configured - COMPLETED"


# 1.4.3 Ensure authentication required for single user mode
echo "1.4.3 Ensure authentication required for single user mode - STARTING"
echo "auth required pam_securetty.so" > /etc/pam.d/single-user
echo "1.4.3 Ensure authentication required for single user mode - COMPLETED"


# 1.6.1.1 Ensure AppArmor is installed - apparmor-utils
echo "1.6.1.1 Ensure AppArmor is installed - apparmor-utils - STARTING"
apt-get install -y apparmor-utils
echo "1.6.1.1 Ensure AppArmor is installed - apparmor-utils - COMPLETED"

# 2.1.2.1 Ensure chrony is configured with authorized timeserver
echo "2.1.2.1 Ensure chrony is configured with authorized timeserver - STARTING"
apt-get install -y chrony
echo "server sg.pool.ntp.org iburst" > /etc/chrony/chrony.conf
systemctl enable chronyd
systemctl start chronyd
echo "2.1.2.1 Ensure chrony is configured with authorized timeserver - COMPLETED"

# 2.2.16 Ensure rsync service is either not installed or masked
echo "2.2.16 Ensure rsync service is either not installed or masked - STARTING"
if systemctl is-active --quiet rsync; then
    echo "Masking rsync service..."
    systemctl stop rsync
    systemctl mask rsync
else
    echo "rsync service is not active. Ensuring it is masked..."
    systemctl mask rsync
fi
echo "2.2.16 Ensure rsync service is either not installed or masked - COMPLETED"




#4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - auditctl
#4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - auditd
#4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - ausearch
#4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - aureport
#4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - autrace
#4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - augenrules

echo "4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - auditctl - STARTING"
echo "4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - auditd - STARTING"
echo "4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - ausearch - STARTING"
echo "4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - aureport - STARTING"
echo "4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - autrace - STARTING"
echo "4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - augenrules - STARTING" 

#4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - auditctl
echo "Updating AIDE configuration to monitor audit tools..."

# Backup existing AIDE configuration
cp /etc/aide/aide.conf /etc/aide/aide.conf.backup

# Add audit tools to AIDE configuration
cat <<EOT >> /etc/aide/aide.conf
# Audit tools integrity check
/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512
EOT

# Note: The above rules assume these binaries exist and AIDE is configured to understand these attributes.
# You may need to adjust the attributes based on what AIDE is configured to handle and what is relevant.

#echo "Reinitializing AIDE to apply new configurations..."
#yes | aideinit


# Check if aideinit was successful
if [ -f /var/lib/aide/aide.db.new ]; then
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    echo "AIDE reinitialized successfully with updated configuration."
else
    echo "Failed to reinitialize AIDE. Check for errors in output."
fi

echo "4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - auditctl - COMPLETED"
echo "4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - auditd - COMPLETED"
echo "4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - ausearch - COMPLETED"
echo "4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - aureport - COMPLETED"
echo "4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - autrace - COMPLETED"
echo "4.1.4.11 Ensure cryptographic mechanisms are used to protect the integrity of audit tools - augenrules - COMPLETED" 



# 4.2.2.3 Ensure journald is configured to send logs to rsyslog
echo "4.2.2.3 Ensure journald is configured to send logs to rsyslog - STARTING"
echo "ForwardToSyslog=yes" >> /etc/systemd/journald.conf
systemctl restart systemd-journald
echo "4.2.2.3 Ensure journald is configured to send logs to rsyslog - COMPLETED"

# 4.2.3 Ensure all logfiles have appropriate access configured
echo "4.2.3 Ensure all logfiles have appropriate access configured - STARTING"
find /var/log -type f -exec chmod g-wx,o-rwx {} +
echo "4.2.3 Ensure all logfiles have appropriate access configured - COMPLETED"

# 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured
echo "5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured - STARTING"
chmod 600 /etc/ssh/sshd_config
echo "5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured - COMPLETED"

# 5.2.17 Ensure SSH warning banner is configured
echo "5.2.17 Ensure SSH warning banner is configured - STARTING"
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
systemctl restart sshd
echo "5.2.17 Ensure SSH warning banner is configured - COMPLETED"

# 5.3.2 Ensure sudo commands use pty
echo "5.3.2 Ensure sudo commands use pty - STARTING"
echo "Defaults use_pty" >> /etc/sudoers
echo "5.3.2 Ensure sudo commands use pty - COMPLETED"

# 5.3.3 Ensure sudo log file exists
echo "5.3.3 Ensure sudo log file exists - STARTING"
echo "Defaults logfile=\"/var/log/sudo.log\"" >> /etc/sudoers
echo "5.3.3 Ensure sudo log file exists - COMPLETED"

# 5.3.7 Ensure access to the su command is restricted
echo "5.3.7 Ensure access to the su command is restricted - STARTING"
echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
echo "SU_WHEEL_ONLY yes" >> /etc/login.defs
echo "5.3.7 Ensure access to the su command is restricted - COMPLETED"


#5.5.5 Ensure default user shell timeout is 900 seconds or less - /etc/bash.bashrc
#5.5.5 Ensure default user shell timeout is 900 seconds or less - /etc/profile /etc/profile.d

echo "5.5.5 Ensure default user shell timeout is 900 seconds or less - /etc/bash.bashrc - STARTING"
echo "5.5.5 Ensure default user shell timeout is 900 seconds or less - /etc/profile /etc/profile.d - STARTING"


# Set the timeout value
TMOUT_VALUE=900

# Function to configure TMOUT in a given file
configure_tmout() {
    local file=$1

    # Backup the file
    cp "$file" "${file}.bak"

    # Check if TMOUT is already configured and skip if it is
    if ! grep -q "TMOUT=$TMOUT_VALUE" "$file"; then
        # Remove existing TMOUT settings to prevent duplication
        sed -i '/^# Set shell timeout/d' "$file"
        sed -i '/^TMOUT=/d' "$file"
        sed -i '/^export TMOUT/d' "$file"
        sed -i '/^readonly TMOUT/d' "$file"

        # Add new TMOUT settings
        echo "# Set shell timeout" >> "$file"
        echo "TMOUT=$TMOUT_VALUE" >> "$file"
        echo "readonly TMOUT" >> "$file"
        echo "export TMOUT" >> "$file"
    fi
}

# Define the files to configure
CONFIG_FILES=(
    "/etc/bash.bashrc"
    "/etc/profile"
)

# Apply settings to /etc/bash.bashrc and /etc/profile
for file in "${CONFIG_FILES[@]}"; do
    if [ -f "$file" ]; then
        configure_tmout "$file"
    fi
done

# Apply settings to all applicable *.sh files in /etc/profile.d/
for file in /etc/profile.d/*.sh; do
    if [ -f "$file" ]; then
        configure_tmout "$file"
    fi
done

echo "5.5.5 Ensure default user shell timeout is 900 seconds or less - /etc/bash.bashrc - COMPLETED"
echo "5.5.5 Ensure default user shell timeout is 900 seconds or less - /etc/profile /etc/profile.d - COMPLETED"



# 6.1.9 Ensure no world writable files exist
echo "6.1.9 Ensure no world writable files exist - STARTING"
find / -xdev -type f -perm -0002 -exec chmod o-w {} \;
echo "6.1.9 Ensure no world writable files exist - COMPLETED"

# 6.1.10 Ensure no unowned files or directories exist
echo "6.1.10 Ensure no unowned files or directories exist - STARTING"
find / -xdev -nouser -exec chown root:root {} \;
echo "6.1.10 Ensure no unowned files or directories exist - COMPLETED"

# 6.1.11 Ensure no ungrouped files or directories exist
echo "6.1.11 Ensure no ungrouped files or directories exist - STARTING"
find / -xdev -nogroup -exec chgrp root {} \;
echo "6.1.11 Ensure no ungrouped files or directories exist - COMPLETED"

# 6.2.13 Ensure local interactive user home directories are mode 750 or more restrictive
echo "6.2.13 Ensure local interactive user home directories are mode 750 or more restrictive - STARTING"
find /home -mindepth 1 -maxdepth 1 -type d -exec chmod 750 {} \;
echo "6.2.13 Ensure local interactive user home directories are mode 750 or more restrictive - COMPLETED"

# 4.2.2.5 Ensure logging is configured
echo "4.2.2.5 Ensure logging is configured - STARTING"
echo "*.info;mail.none;authpriv.none;cron.none   /var/log/messages" >> /etc/rsyslog.conf
echo "4.2.2.5 Ensure logging is configured - COMPLETED"

# 4.2.2.6 Ensure rsyslog is configured to send logs to a remote log host
echo "4.2.2.6 Ensure rsyslog is configured to send logs to a remote log host - STARTING"
echo "*.* @@remote-host:514" >> /etc/rsyslog.conf
systemctl restart rsyslog
echo "4.2.2.6 Ensure rsyslog is configured to send logs to a remote log host - COMPLETED"

# 5.2.4 Ensure SSH access is limited by DenyGroups
echo "5.2.4 Ensure SSH access is limited by DenyGroups - STARTING"
echo "DenyUsers cloud-user" >> /etc/ssh/sshd_config
systemctl restart sshd
echo "5.2.4 Ensure SSH access is limited by DenyGroups - COMPLETED"


# 5.2.18 Ensure SSH MaxAuthTries is set to 4 or less
echo "5.2.18 Ensure SSH MaxAuthTries is set to 4 or less - STARTING"
sed -i '/^MaxAuthTries/d' /etc/ssh/sshd_config
echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
echo "5.2.18 Ensure SSH MaxAuthTries is set to 4 or less - COMPLETED"

# 5.2.19 Ensure SSH MaxStartups is configured
echo "5.2.19 Ensure SSH MaxStartups is configured - STARTING"
sed -i '/^MaxStartups/d' /etc/ssh/sshd_config
echo "MaxStart"
echo "5.2.19 Ensure SSH MaxStartups is configured - COMPLETED"


# 5.2.21 Ensure SSH LoginGraceTime is set to one minute or less
echo "5.2.21 Ensure SSH LoginGraceTime is set to one minute or less - STARTING"
sed -i '/^LoginGraceTime/d' /etc/ssh/sshd_config
echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
systemctl restart sshd
echo "5.2.21 Ensure SSH LoginGraceTime is set to one minute or less - COMPLETED"


# 5.4.1 Ensure password creation requirements are configured
echo "5.4.1 Ensure password creation requirements are configured - STARTING"

# Install necessary package
echo "Installing libpam-pwquality..."
apt-get install -y libpam-pwquality

# Configure password quality requirements
PWQUALITY_CONF="/etc/security/pwquality.conf"
cp $PWQUALITY_CONF $PWQUALITY_CONF.backup

# Set minimum password length
echo "minlen = 14" >> $PWQUALITY_CONF

# Set password complexity requirements
echo "minclass = 4" >> $PWQUALITY_CONF
# Alternative complexity settings
#echo "dcredit = -1" >> $PWQUALITY_CONF
#echo "ucredit = -1" >> $PWQUALITY_CONF
#echo "ocredit = -1" >> $PWQUALITY_CONF
#echo "lcredit = -1" >> $PWQUALITY_CONF

echo "5.4.1 Ensure password creation requirements are configured - COMPLETED"


# 5.4.2 Ensure lockout for failed password attempts is configured

# Configure PAM to use faillock for handling failed password attempts
echo "5.4.2 Ensure lockout for failed password attempts is configured - STARTING"

echo "Configuring PAM for password attempt lockouts..."
COMMON_AUTH="/etc/pam.d/common-auth"
cp $COMMON_AUTH $COMMON_AUTH.backup

# Adding faillock before pam_unix
sed -i '/pam_unix.so/ i\auth required pam_faillock.so preauth' $COMMON_AUTH
# Adding faillock after pam_unix
sed -i '/pam_unix.so/ a\auth [default=die] pam_faillock.so authfail' $COMMON_AUTH
sed -i '/pam_faillock.so authfail/ a\auth sufficient pam_faillock.so authsucc' $COMMON_AUTH

COMMON_ACCOUNT="/etc/pam.d/common-account"
cp $COMMON_ACCOUNT $COMMON_ACCOUNT.backup

# Ensure faillock is enabled in common-account
echo "account required pam_faillock.so" >> $COMMON_ACCOUNT

# Configure faillock settings
echo "Configuring faillock settings..."
FAILLOCK_CONF="/etc/security/faillock.conf"
cp $FAILLOCK_CONF $FAILLOCK_CONF.backup

echo "deny = 4" > $FAILLOCK_CONF
echo "fail_interval = 900" >> $FAILLOCK_CONF
echo "unlock_time = 600" >> $FAILLOCK_CONF

echo "5.4.2 Ensure lockout for failed password attempts is configured - COMPLETED"


# 5.4.4 Updating password hashing algorithm to the latest standards.
echo "5.4.4 Updating password hashing algorithm to the latest standards - STARTING"

# Step 1: Update /etc/pam.d/common-password
# Backup the original file before making changes
echo "Backing up and updating PAM configuration..."
cp /etc/pam.d/common-password /etc/pam.d/common-password.backup

# Update the line containing pam_unix.so to ensure no specific hashing algorithm is set and add yescrypt option
sed -i '/pam_unix.so/ c\password    [success=1 default=ignore]    pam_unix.so obscure use_authtok try_first_pass remember=5' /etc/pam.d/common-password

echo "PAM configuration updated."

# Step 2: Update /etc/login.defs to set yescrypt as the hashing method
# Backup the original file before making changes
echo "Backing up and updating login definitions..."
cp /etc/login.defs /etc/login.defs.backup

# Set ENCRYPT_METHOD to yescrypt
sed -i '/^ENCRYPT_METHOD/ c\ENCRYPT_METHOD yescrypt' /etc/login.defs

# If ENCRYPT_METHOD line does not exist, add it
grep -q '^ENCRYPT_METHOD' /etc/login.defs || echo "ENCRYPT_METHOD yescrypt" >> /etc/login.defs

# Final restart of services to apply changes
systemctl restart sshd

echo "5.4.4 Updating password hashing algorithm to the latest standards - COMPLETED"



# 3.5.3.2.2 Ensure iptables loopback traffic is configured
echo "3.5.3.2.2 Ensure iptables loopback traffic is configured - STARTING"
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
echo "3.5.3.2.2 Ensure iptables loopback traffic is configured - COMPLETED"

# 3.5.3.2.3 Ensure iptables outbound and established connections are configured
echo "3.5.3.2.3 Ensure iptables outbound and established connections are configured - STARTING"
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
echo "3.5.3.2.3 Ensure iptables outbound and established connections are configured - COMPLETED"

# 3.5.3.2.4 Ensure iptables firewall rules exist for all open ports
echo "3.5.3.2.4 Ensure iptables firewall rules exist for all open ports - STARTING"
iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # Example for SSH port
echo "3.5.3.2.4 Ensure iptables firewall rules exist for all open ports - COMPLETED"

# 3.5.3.3.2 Ensure ip6tables loopback traffic is configured
echo "3.5.3.3.2 Ensure ip6tables loopback traffic is configured - STARTING"
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT
echo "3.5.3.3.2 Ensure ip6tables loopback traffic is configured - COMPLETED"

# 3.5.3.3.3 Ensure ip6tables outbound and established connections are configured
echo "3.5.3.3.3 Ensure ip6tables outbound and established connections are configured - STARTING"
ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
echo "3.5.3.3.3 Ensure ip6tables outbound and established connections are configured - COMPLETED"

# 3.5.3.3.4 Ensure ip6tables firewall rules exist for all open ports
echo "3.5.3.3.4 Ensure ip6tables firewall rules exist for all open ports - STARTING"
ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT  # Example for SSH port
echo "3.5.3.3.4 Ensure ip6tables firewall rules exist for all open ports - COMPLETED"

# Define paths to exclude from the search properly
EXCLUDE_PATHS="/proc /sys /run /dev"

# 6.1.12 Audit SUID executables
echo "6.1.12 Audit SUID executables - STARTING"
find / -type f \( $(printf "! -path %s " $EXCLUDE_PATHS) \) -perm -4000 -exec ls -la {} + > /var/log/suid_files.txt
echo "6.1.12 Audit SUID executables - COMPLETED"

# 6.1.13 Audit SGID executables
echo "6.1.13 Audit SGID executables - STARTING"
find / -type f \( $(printf "! -path %s " $EXCLUDE_PATHS) \) -perm -2000 -exec ls -la {} + > /var/log/sgid_files.txt
echo "6.1.13 Audit SGID executables - COMPLETED"

# 5.4.5 Ensure all current passwords use the SHA-512 hashing algorithm
echo "5.4.5 Ensure all current passwords use the SHA-512 hashing algorithm - STARTING"
sed -i '/^password.*pam_unix.so/ s/$/ sha512/' /etc/pam.d/common-password
echo "5.4.5 Ensure all current passwords use the SHA-512 hashing algorithm - COMPLETED"


# 3.5.3.1.1 Ensure iptables packages are installed - iptables-persistent
echo "3.5.3.1.1 Ensure iptables packages are installed - iptables-persistent - STARTING"
DEBIAN_FRONTEND=noninteractive apt-get install iptables-persistent -y

# Save current iptables IPv4 rules
echo "Saving current iptables IPv4 rules..."
iptables-save > /etc/iptables/rules.v4
echo "IPv4 iptables rules have been saved to /etc/iptables/rules.v4."

# Confirm the rules are set to load on boot
systemctl enable netfilter-persistent
echo "3.5.3.1.1 Ensure iptables packages are installed - iptables-persistent - COMPLETED"



#3.5.3.2.1 Ensure iptables default deny firewall policy - 'Chain INPUT'
#3.5.3.2.1 Ensure iptables default deny firewall policy - 'Chain OUTPUT'

echo "3.5.3.2.1 Ensure iptables default deny firewall policy - 'Chain INPUT'  - STARTING"
echo "3.5.3.2.1 Ensure iptables default deny firewall policy - 'Chain OUTPUT' - STARTING"


# Define iptables rules and save them to /etc/iptables/rules.v4

cat <<EOF > /etc/iptables/rules.v4
# Generated by iptables-save v1.8.7 
*filter
:INPUT DROP [0:0]   # Default policy set to DROP for INPUT
:FORWARD DROP [0:0] # Default policy remains DROP for FORWARD
:OUTPUT DROP [0:0]  # Default policy set to DROP for OUTPUT
:DOCKER - [0:0]
:DOCKER-ISOLATION-STAGE-1 - [0:0]
:DOCKER-ISOLATION-STAGE-2 - [0:0]
:DOCKER-USER - [0:0]
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-ISOLATION-STAGE-1
-A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -o docker0 -j DOCKER
-A FORWARD -i docker0 ! -o docker0 -j ACCEPT
-A FORWARD -i docker0 -o docker0 -j ACCEPT
-A DOCKER-ISOLATION-STAGE-1 -i docker0 ! -o docker0 -j DOCKER-ISOLATION-STAGE-2
-A DOCKER-ISOLATION-STAGE-1 -j RETURN
-A DOCKER-ISOLATION-STAGE-2 -o docker0 -j DROP
-A DOCKER-ISOLATION-STAGE-2 -j RETURN
-A DOCKER-USER -j RETURN
# Specific subnet allowances
-A INPUT -s 10.0.0.0/8 -j ACCEPT 
-A OUTPUT -d 10.0.0.0/8 -j ACCEPT
# General allowances
-A INPUT -j ACCEPT 
-A OUTPUT -j ACCEPT
COMMIT
# Completed on Fri May 10 09:05:02 2024

# Generated by iptables-save v1.8.7 
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:DOCKER - [0:0]
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
-A DOCKER -i docker0 -j RETURN
COMMIT
EOF

# Apply iptables rules from the file
iptables-restore < /etc/iptables/rules.v4
echo "iptables rules set and restored from /etc/iptables/rules.v4."

# Save the iptables rules to ensure they persist after reboot
netfilter-persistent save
echo "iptables rules have been saved and will persist after reboot."

echo "3.5.3.2.1 Ensure iptables default deny firewall policy - 'Chain INPUT'  - COMPLETED"
echo "3.5.3.2.1 Ensure iptables default deny firewall policy - 'Chain OUTPUT' - COMPLETED"


#3.5.3.3.1 Ensure ip6tables default deny firewall policy - 'Chain INPUT'
#3.5.3.3.1 Ensure ip6tables default deny firewall policy - 'Chain FORWARD'
#3.5.3.3.1 Ensure ip6tables default deny firewall policy - 'Chain OUTPUT'


echo "3.5.3.3.1 Ensure ip6tables default deny firewall policy - 'Chain INPUT' - STARTING"
echo "3.5.3.3.1 Ensure ip6tables default deny firewall policy - 'Chain FORWARD' - STARTING"
echo "3.5.3.3.1 Ensure ip6tables default deny firewall policy - 'Chain OUTPUT' - STARTING"

# Set all default policies to DROP
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP

echo "Default policies set to DROP for all chains."

# Save the ip6tables rules to ensure they persist after reboot
if command -v ip6tables-save > /dev/null && command -v ip6tables-apply > /dev/null; then
    ip6tables-save > /etc/ip6tables/rules.v6
    echo "ip6tables rules have been saved."
else
    echo "Error: ip6tables-save or ip6tables-apply not found. Ensure iptables-persistent is installed or manually save the rules."
fi

echo "3.5.3.3.1 Ensure ip6tables default deny firewall policy - 'Chain INPUT' - COMPLETED"
echo "3.5.3.3.1 Ensure ip6tables default deny firewall policy - 'Chain FORWARD' - COMPLETED"
echo "3.5.3.3.1 Ensure ip6tables default deny firewall policy - 'Chain OUTPUT' - COMPLETED"



#1.1.2.1 Ensure /tmp is a separate partition
#1.1.2.2 Ensure nodev option set on /tmp partition
#1.1.2.3 Ensure noexec option set on /tmp partition
#1.1.2.4 Ensure nosuid option set on /tmp partition


echo "1.1.2.1 Ensure /tmp is a separate partition - STARTING"
echo "1.1.2.2 Ensure nodev option set on /tmp partition - STARTING"
echo "1.1.2.3 Ensure noexec option set on /tmp partition - STARTING"
echo "1.1.2.4 Ensure nosuid option set on /tmp partition - STARTING"


# Update package list and install fdisk and parted
apt-get install -y fdisk 


# Unmount /tmp if it is already mounted somewhere
umount /tmp 2>/dev/null

# Use fdisk to resize sda1 and create sda2
{
echo d # Delete partition
echo 1 # Partition number 1
echo n # Add a new partition
echo p # Primary partition
echo 1 # Partition number 1
echo   # First sector (accept default: 2048)
echo +90G # Last sector for sda1, shrink to make space for sda2
echo n # New partition
echo p # Primary partition
echo 2 # Partition number 2
echo   # First sector (accept default)
echo   # Last sector (accept default, uses remaining space)
echo w # Write changes
} | fdisk /dev/sda

# Inform OS of partition table changes
partprobe

# Format the new partition as ext4
mkfs.ext4 /dev/sda2

# Create a mount point for /tmp
mkdir -p /tmp

# Mount the new partition to /tmp
mount /dev/sda2 /tmp

# Set permissions for /tmp directory
chmod 1777 /tmp

# Backup the existing /etc/fstab
cp /etc/fstab /etc/fstab.backup

# Add or update the /tmp entry
if grep -q '/tmp' /etc/fstab; then
    # Modify the existing /tmp entry
    sed -i '/\/tmp/ s/defaults/nodev,nosuid,noexec/' /etc/fstab
else
    # Add new entry if /tmp is not in fstab
    echo '/dev/sda2 /tmp ext4 nodev,nosuid,noexec 0 0' >> /etc/fstab
fi



# Optional: Copy current /tmp files to the new partition
# cp -a /tmp_old/* /tmp/


# Reload fstab to mount all
mount -a

echo "1.1.2.1 Ensure /tmp is a separate partition - COMPLETED"
echo "1.1.2.2 Ensure nodev option set on /tmp partition - COMPLETED"
echo "1.1.2.3 Ensure noexec option set on /tmp partition - COMPLETED"
echo "1.1.2.4 Ensure nosuid option set on /tmp partition - COMPLETED"



#1.1.8.2 Ensure noexec option set on /dev/shm partition
echo "1.1.8.2 Ensure noexec option set on /dev/shm partition - STARTING"
if grep -q '/dev/shm' /etc/fstab; then
    # Modify the existing /dev/shm entry
    sed -i '/\/dev\/shm/ s/defaults/nodev,noexec,nosuid/' /etc/fstab
else
    # Add new entry if /dev/shm is not in fstab
    echo 'tmpfs /dev/shm tmpfs nodev,noexec,nosuid 0 0' >> /etc/fstab
fi

# Reload fstab to mount all again
mount -a
echo "1.1.8.2 Ensure noexec option set on /dev/shm partition - COMPLETED"




# Check the current version of OpenSSL
CURRENT_VERSION=$(openssl version)
ECHO "Check if the current version is the vulnerable version - STARTING"
echo "Current OpenSSL version: $CURRENT_VERSION"

# Define the vulnerable version range
VULN_VERSION="OpenSSL 3.2.0"

# Check if the current version is the vulnerable version
if [[ "$CURRENT_VERSION" == *"$VULN_VERSION"* ]]; then
    echo "Vulnerable version of OpenSSL detected: $CURRENT_VERSION"
    echo "Updating OpenSSL to the latest version..."

    # Update the package lists
    apt-get update

    # Upgrade OpenSSL
    apt-get install --only-upgrade openssl -y

    # Check if the upgrade was successful
    if [[ "$(openssl version)" != *"$VULN_VERSION"* ]]; then
        echo "OpenSSL has been successfully updated to $(openssl version)"
    else
        echo "Failed to update OpenSSL. Further investigation is required."
    fi
else
    echo "No vulnerable version of OpenSSL detected. No action needed. - COMPLETED"
fi





##########################  OS Hardening Script End Here  #################################  
