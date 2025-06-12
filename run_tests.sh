#!/bin/bash

helpFunction()
{
   echo ""
   echo "Usage: $0 -r <runs> -l <loss> -p <burst loss probability> -d <delay> -j <delay std dev> -n <number of messages> -s <size of messages> -i <message interval> -q <QoS> -k <KeepAlive>"
   echo -e "\t-r number of times to run each test"
   echo -e "\t-l link loss probability (e.g., 1%)"
   echo -e "\t-p burst loss probability (e.g., 25%)"
   echo -e "\t-d delay (e.g., 20ms)"
   echo -e "\t-j delay std dev (e.g., 5ms) for jitter"
   echo -e "\t-n number of messages to send"
   echo -e "\t-s size of each message in bytes"
   echo -e "\t-i interval between messages (in seconds)"
   echo -e "\t-q QoS level (0, 1, or 2)"
   echo -e "\t-k KeepAlive value (in seconds)"
   echo -e "Example: $0 -r 10 -l 1% -p 25% -d 20ms -j 5ms -n 10 -s 100 -i 1 -q 1 -k 60"
   exit 1
}

while getopts "r:l:p:d:j:n:s:i:q:k:" opt; do
   case "$opt" in
      r ) runs="$OPTARG" ;;
      l ) loss="$OPTARG" ;;
      p ) burstloss="$OPTARG" ;;
      d ) delay="$OPTARG" ;;
      j ) delaystddev="$OPTARG" ;;
      n ) number_of_packets="$OPTARG" ;;
      s ) size_of_packets="$OPTARG" ;;
      i ) msg_interval="$OPTARG" ;;
      q ) qos="$OPTARG" ;;
      k ) keepalive="$OPTARG" ;;
      ? ) helpFunction ;;
   esac
done

if [ -z "$runs" ] || [ -z "$loss" ] || [ -z "$burstloss" ] || [ -z "$delay" ] || [ -z "$delaystddev" ] || [ -z "$number_of_packets" ] || [ -z "$size_of_packets" ] || [ -z "$msg_interval" ] || [ -z "$qos" ] || [ -z "$keepalive" ]; then
   echo "Some or all of the parameters are empty"
   helpFunction
fi

docker compose up -d
container_id=$(docker compose ps -q)
sleep 10

iflink=$(docker exec -it "$container_id" bash -c 'cat /sys/class/net/eth0/iflink' | tr -d '\r')
veth=$(grep -l "$iflink" /sys/class/net/veth*/ifindex)
veth=$(echo "$veth" | sed -e 's;^.*net/\(.*\)/ifindex$;\1;')
echo "$container_id:$veth"

sudo modprobe ifb
sudo ip link set dev ifb0 up
sudo tc qdisc add dev "$veth" ingress
sudo tc filter add dev "$veth" parent ffff: protocol ip u32 match u32 0 0 flowid 1:1 action mirred egress redirect dev ifb0
sudo tc qdisc add dev "$veth" root netem delay "$delay" "$delaystddev" loss "$loss" "$burstloss"
sudo tc qdisc add dev ifb0 root netem delay "$delay" "$delaystddev" loss "$loss" "$burstloss"

mkdir -p ./results/sn-dtls

#r build -f Dockerfile -t mqtt-sn-client:0.1 .

x=1
while [ "$x" -le "$runs" ]; do
   echo "Running test $x of $runs..."
   sudo tcpdump -U -i "$veth" port 8883 -w "./results/sn-dtls/run-$x-loss-$loss-delay-$delay-n-$number_of_packets-s-$size_of_packets-i-$msg_interval.pcap" &
   sleep 5

   for i in $(seq 1 "$number_of_packets"); do
      msg=$(head -c "$size_of_packets" < /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c "$size_of_packets")
      echo "docker run --rm --network=mqtt-sn-tools_emqx-bridge mqtt-sn-client:0.1 ./mqtt-sn-pub -h broker.emqx.io -p 8883 --dtls -i mqtt-sn-tools-$$ -t test/topic -m $msg -q $qos -k $keepalive"
      docker run --rm --network=mqtt-sn-tools_emqx-bridge mqtt-sn-client:0.1 ./mqtt-sn-pub  \
            -h broker.emqx.io \
            -p 8883 \
            --dtls \
            -i "mqtt-sn-tools-$$" \
            -t "test/topic" \
            -m "$msg" \
            -q "$qos" \
            -k "$keepalive"
      sleep "$msg_interval"
   done

   pid=$(pgrep tcpdump)
   sleep 5
   sudo kill -2 "$pid"
   x=$((x + 1))
done

sudo tc qdisc del dev "$veth" root
sudo tc qdisc del dev "$veth" handle ffff: ingress
sudo modprobe -r ifb

docker compose down
docker system prune -f
