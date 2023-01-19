#!/bin/sh

mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n  KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n  MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n  HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com\n" >> ~/.ssh/config

/usr/bin/sudo /usr/bin/grep -q '^Ciphers' /etc/ssh/sshd_config && /usr/bin/sudo /usr/bin/sed -i.bak 's/^Ciphers.*/Ciphers aes256-ctr,aes192-ctr,aes128-ctr/' /etc/ssh/sshd_config || /usr/bin/sudo /usr/bin/sed -i.bak '/.*Ciphers and keying.*/a\'$'\nCiphers aes256-ctr,aes192-ctr,aes128-ctr'$'\n' /etc/ssh/sshd_config
/usr/bin/sudo /usr/bin/grep -q '^MACs' /etc/ssh/sshd_config && /usr/bin/sudo /usr/bin/sed -i.bak 's/^MACs.*/MACs hmac-sha2-256,hmac-sha2-512/' /etc/ssh/sshd_config || /usr/bin/sudo /usr/bin/sed -i.bak '/.*Ciphers and keying.*/a\'$'\nMACs hmac-sha2-512,hmac-sha2-256'$'\n' /etc/ssh/sshd_config
/usr/bin/sudo /usr/bin/grep -q '^KexAlgorithms' /etc/ssh/sshd_config && /usr/bin/sudo /usr/bin/sed -i.bak 's/^KexAlgorithms.*/KexAlgorithms diffie-hellman-group-exchange-sha256/' /etc/ssh/sshd_config || /usr/bin/sudo /usr/bin/sed -i.bak '/.*Ciphers and keying.*/a\'$'\nKexAlgorithms diffie-hellman-group-exchange-sha256'$'\n' /etc/ssh/sshd_config
