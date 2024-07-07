
# netfilter-exporter

Export iptabels/nftables statistics as prometheus metrics. 

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![Build Status](https://github.com/ne-bknn/exporter-merger/actions/workflows/build.yml/badge.svg)]()
[![codecov](https://codecov.io/gh/ne-bknn/netfilter-exporter/branch/master/graph/badge.svg?token=A85S07L6P5)](https://codecov.io/gh/ne-bknn/exporter-merger)

## Deployment

To deploy this project run

```bash
  go build netfilter-exporter.go
  ./netfilter-exporter
```

## Roadmap

- [ ] Default machine-wide metrics
- [ ] nftables support


