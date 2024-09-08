
# netfilter-exporter

Export iptabels/nftables statistics as prometheus metrics. Inspired by [Scaling Kubernetes to 7,500 nodes](https://openai.com/index/scaling-kubernetes-to-7500-nodes/).

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg?style=flat)](https://choosealicense.com/licenses/mit/)
[![Build Status](https://github.com/ne-bknn/exporter-merger/actions/workflows/build.yml/badge.svg)]()
[![codecov](https://codecov.io/gh/ne-bknn/netfilter-exporter/branch/master/graph/badge.svg?token=A85S07L6P5)](https://codecov.io/gh/ne-bknn/exporter-merger)
[![Continious Benchmarking](https://img.shields.io/badge/Continious%20Benchmarking-515151)](https://ne-bknn.github.io/netfilter-exporter/dev/bench/)

## Deployment

To deploy this project run

```
$ go build netfilter-exporter.go
# ./netfilter-exporter
```

## Usage

This exporter tracks either nftables or iptables rules that have comments with prefix `netfilter-exporter`. For example, for nft rule can be:

```
sudo nft add rule ip mangle INPUT ip saddr 192.168.1.1 accept comment \"netfilter-exporter foo=bar\"
```

and for iptables

```
sudo iptables -A OUTPUT -d 1.1.1.1 -m comment --comment "netfilter-exporter dest=cloudflare" -j LOG
```

After the `netfilter-exporter` prefix you can specify key=value pairs; they will become metric labels. I.e. creating previously mentioned iptables rule will expose the following metrics:
```
# HELP firewall_rule_byte_count Number of bytes matching the firewall rule
# TYPE firewall_rule_byte_count counter
firewall_rule_byte_count{chain="OUTPUT",dest="cloudflare",table="filter"} 3450
# HELP firewall_rule_packet_count Number of packets matching the firewall rule
# TYPE firewall_rule_packet_count counter
firewall_rule_packet_count{chain="OUTPUT",dest="cloudflare",table="filter"} 32
```

Please read [prometheus metric and label naming best practices](https://prometheus.io/docs/practices/naming/) before proceeding.

## Roadmap

- [ ] Default machine-wide metrics
- [ ] nftables support
- [ ] Docker images

