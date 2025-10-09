#!/usr/bin/env bash

set -eu

# ========== CONFIGURATION ==========
CHAINCODE_NAME="on_chain_pir"
CHAINCODE_VERSION="0.0.1"
CHANNEL_NAME="channel-mini"
PEER_IP="0.0.0.0"
PEER_NAME="peer0.org1.example.com"
CHAINCODE_DIR="."  # Current directory or path to your Go chaincode

# ========== CHECK COMMANDS ==========
for cmd in docker go grep awk; do
    if ! command -v $cmd &>/dev/null; then
        echo "Error: '$cmd' command not found. Please install it first."
        exit 1
    fi
done

# ========== VALIDATE GO CHAINCODE ==========
if [ ! -f "main.go" ]; then
    echo "Error: main.go file not found in current directory."
    echo "Please run this script from your Go chaincode directory."
    exit 1
fi

# ========== VALIDATE PEER CONTAINER ==========
if ! docker ps | grep -q "$PEER_NAME"; then
    echo "Error: $PEER_NAME container is not running."
    echo "Please make sure the Fabric network is up and running."
    exit 1
fi

# ========== GET CORRECT CHAINCODE PORT ==========
# Try different possible chaincode ports
CHAINCODE_PORT=""
for port in 7052 7050 9999; do
    if docker port "$PEER_NAME" $port 2>/dev/null | grep -q '0.0.0.0'; then
        CHAINCODE_PORT=$(docker port "$PEER_NAME" $port | grep '0.0.0.0' | awk -F: '{print $2}' | head -n1)
        echo "Found chaincode port mapping: container $port -> host $CHAINCODE_PORT"
        break
    fi
done

if [ -z "$CHAINCODE_PORT" ]; then
    echo "Error: Could not find chaincode port mapping."
    echo "Available ports for $PEER_NAME:"
    docker port "$PEER_NAME"
    echo ""
    echo "Please check your Fablo configuration for the chaincode port."
    exit 1
fi

echo "Testing connectivity to peer at $PEER_IP:$CHAINCODE_PORT..."
if ! nc -z $PEER_IP $CHAINCODE_PORT 2>/dev/null; then
    echo "Error: Cannot connect to peer chaincode port $PEER_IP:$CHAINCODE_PORT."
    echo "Ensure the peer is running in dev mode and listening on port $CHAINCODE_PORT."
    exit 1
fi

# ========== EXPORT ENVIRONMENT VARIABLES ==========
export CORE_CHAINCODE_ID_NAME="$CHAINCODE_NAME:$CHAINCODE_VERSION"
export CORE_CHAINCODE_LOGGING_LEVEL="DEBUG"
export CORE_CHAINCODE_LOGGING_SHIM="debug"
export CORE_PEER_TLS_ENABLED=false
export CORE_CHAINCODE_LOGLEVEL=debug
export FABRIC_LOGGING_SPEC=debug

# ========== RUN GO CHAINCODE ==========
echo "========================================"
echo "Running Go chaincode in dev mode..."
echo "Chaincode Name: $CORE_CHAINCODE_ID_NAME"
echo "Peer Address: $PEER_IP:$CHAINCODE_PORT"
echo "Using 'go run' to start chaincode..."
echo "========================================"

# Run the chaincode directly with go run
go run . -peer.address=$PEER_IP:$CHAINCODE_PORT