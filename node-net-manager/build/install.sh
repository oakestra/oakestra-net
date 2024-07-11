sudo cp ./NetManager /bin/NetManager
sudo mkdir /etc/netmanager >/dev/null 2>&1
sudo mkdir /var/log/netmanager >/dev/null 2>&1

if [ ! -e /etc/netmanager/netcfg.json ]
then
    if [ -e tuncfg.json ]
    then
        sudo cp tuncfg.json /etc/netmanager/tuncfg.json
        sudo cp netcfg.json /etc/netmanager/netcfg.json
    else
        sudo cp ../config/tuncfg.json /etc/netmanager/tuncfg.json
        sudo cp ../config/netcfg.json /etc/netmanager/netcfg.json
    fi
fi

if [ -e netmanager.service ]
then
    sudo cp netmanager.service /etc/systemd/system/netmanager.service
else
    sudo cp ../netmanager.service /etc/systemd/system/netmanager.service
fi  

sudo chmod 755 /bin/NetManager