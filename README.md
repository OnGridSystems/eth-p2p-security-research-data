# Ethereum P2P Security Toolkit: Datasets, Analysis, and Research Instruments

## Run Ethereum EN + CN stack with telemetry

Prepare the host

```bash
openssl rand -hex 32 > /mnt/jwt.hex
chmod ugo+r /mnt/jwt.hex
mkdir -p /data/lighthouse
mkdir -p /data/reth
mkdir -p /dumps
chmod ugo+rw /dumps
chmod -R ugo+rw /data/
```

Run the stack Execution Node + Consensus Node + Telemetry

```bash
export DOCKER_HOST=ssh://root@host
docker compose up --build -d
```

The telemetry engine will write PCAP files and Peer JSONs to `/dumps` directory.
