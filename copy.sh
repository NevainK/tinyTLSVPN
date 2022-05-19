for host in $*
do
    sudo docker cp ./tcpvpnclient $host:/
    sudo docker cp ./cert_server  $host:/
done
echo "copy finish"
