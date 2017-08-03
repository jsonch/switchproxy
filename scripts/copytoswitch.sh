# copies relevant files to the pica 8 switch @ 10.1.1.1
SWITCHIP=10.1.1.1
SWITCHUSER=admin
SWITCHPW=p1c@ate

sshpass -p $SWITCHPW scp -r ./* $SWITCHUSER@$SWITCHIP:~/timeout_proxy