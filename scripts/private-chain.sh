#!/usr/bin/env bash
# POSIX

set -e

while :; do
  case $1 in
    -f|--first)
      ./target/release/node-template \
        --base-path /tmp/node01 \
        --chain ./customSpecRaw.json \
        --port 30333 \
        --ws-port 9944 \
        --rpc-port 9933 \
        --telemetry-url 'wss://telemetry.polkadot.io/submit/ 0' \
        --validator \
        --rpc-methods=Unsafe \
        --name MyNode01
      exit
      ;;
    -fk|--first-keys)
      curl http://localhost:9933 -H "Content-Type:application/json;charset=utf-8" -d "{\"jsonrpc\":\"2.0\", \"id\":1, \"method\":\"author_insertKey\", \"params\": [\"aura\", \"clip organ olive upper oak void inject side suit toilet stick narrow\", \"0x9effc1668ca381c242885516ec9fa2b19c67b6684c02a8a3237b6862e5c8cd7e\"]}"
      curl http://localhost:9933 -H "Content-Type:application/json;charset=utf-8" -d "{\"jsonrpc\":\"2.0\", \"id\":2, \"method\":\"author_insertKey\", \"params\": [\"gran\", \"clip organ olive upper oak void inject side suit toilet stick narrow\", \"0xb48004c6e1625282313b07d1c9950935e86894a2e4f21fb1ffee9854d180c781\"]}"
      exit
      ;;
    -s|--second)
      PEER_ID=$(curl -s http://localhost:9933 -H "Content-Type:application/json;charset=utf-8" -d "{\"jsonrpc\":\"2.0\", \"id\":1, \"method\":\"system_localPeerId\", \"params\": []}" | jq -r ".result")
      ./target/release/node-template \
        --base-path /tmp/node02 \
        --chain ./customSpecRaw.json \
        --port 30334 \
        --ws-port 9945 \
        --rpc-port 9934 \
        --telemetry-url 'wss://telemetry.polkadot.io/submit/ 0' \
        --validator \
        --rpc-methods=Unsafe \
        --name MyNode02 \
        --bootnodes /ip4/127.0.0.1/tcp/30333/p2p/$PEER_ID
      exit
      ;;
    -sk|--second-keys)
      curl http://localhost:9934 -H "Content-Type:application/json;charset=utf-8" -d "{\"jsonrpc\":\"2.0\", \"id\":1, \"method\":\"author_insertKey\", \"params\": [\"aura\", \"paper next author index wedding frost voice mention fetch waste march tilt\", \"0x74cca68a32156615a5923c67024db70da5e7ed36e70c8cd5bcf3556df152bb6d\"]}"
      curl http://localhost:9934 -H "Content-Type:application/json;charset=utf-8" -d "{\"jsonrpc\":\"2.0\", \"id\":2, \"method\":\"author_insertKey\", \"params\": [\"gran\", \"paper next author index wedding frost voice mention fetch waste march tilt\", \"0x0fe9065f6450c5501df3efa6b13958949cb4b81a2147d68c14ad25366be1ccb4\"]}"
      exit
      ;;
  esac

  shift
done
