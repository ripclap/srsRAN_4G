# X2 handover

This fork adds native X2AP handover to srsENB. The implementation uses SCTP on
port 36422, PPID 27, and a generated APER codec from the X2AP R14.6.0 schema.

## Features

- X2 Setup with peer eNB, cell, and PLMN checks
- Handover Request/Acknowledge and target RRC resource allocation
- AS security context and PDCP SN/HFN transfer
- GTP-U downlink forwarding and S1 Path Switch
- UE Context Release and source bearer cleanup
- Preparation failure, cancellation, and timeout handling

X2 processing runs on the existing stack task queue. The source and target
preparation timers expire after 10,000 radio ticks. X2 preparation failure keeps
the UE on its source cell; it does not trigger S1 handover preparation.

## Build

Install the usual srsRAN dependencies and the codec generation tools. On
Ubuntu 22.04:

```sh
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config git ca-certificates \
  autoconf automake libtool bison flex python3 libfftw3-dev libmbedtls-dev \
  libboost-program-options-dev libconfig++-dev libsctp-dev libzmq3-dev

./tools/build_x2_codec.sh
cmake -S . -B build/enb-x2 -DCMAKE_BUILD_TYPE=Release -DENABLE_WERROR=OFF \
  -DX2AP_CODEC_DIR="$PWD/build/x2ap"
cmake --build build/enb-x2 -j2 --target srsenb srsue
```

The helper downloads the pinned compiler and schema, verifies the schema hash,
and generates the codec under `build/x2ap`. Generated files and compiler sources
stay under `build/`.

For ARM builds, add `-DENABLE_AVX=OFF -DENABLE_AVX2=OFF -DENABLE_AVX512=OFF
-DENABLE_SSE=OFF` to the CMake command.

A regular build without `X2AP_CODEC_DIR` uses the existing S1 handover path.
Requesting X2 at runtime from that build causes a startup error.

### Codec inputs

| Input | Revision |
| --- | --- |
| ASN.1 compiler | [mouse07410/asn1c](https://github.com/mouse07410/asn1c), `940dd5fa9f3917913fd487b13dfddfacd0ded06e` |
| X2AP schema | R14.6.0 from [OpenAirInterface](https://github.com/OPENAIRINTERFACE/openairinterface5g), `29d5fa7d38bb1ee8935ef7ae30a396d53772ea4f` |
| Schema SHA-256 | `cee7f66e1e002a4dfb41db6d01fa7a7b4a74663644ec8ffaeaa4ef7d6f30dbdf` |

## Peer configuration

X2 is enabled per process through environment variables:

| Variable | Value |
| --- | --- |
| `SRSRAN_LAB_X2_PEER` | Peer eNB IPv4 address |
| `SRSRAN_LAB_X2_PEER_ECI` | Peer E-UTRAN cell identifier, `(enb_id << 8) | cell_id` |
| `SRSRAN_LAB_X2_PCI` | Local cell PCI |
| `SRSRAN_LAB_X2_EARFCN` | Local downlink EARFCN; current profile requires `3350` |

Integer values accept decimal or a `0x` hexadecimal prefix. The PCI and EARFCN
must match the local RRC configuration; the peer ECI must match its advertised
cell. The X2 socket binds to `s1c_bind_addr`. Both eNBs need distinct, reachable
S1/GTP addresses and matching PLMN and mobility-domain settings.

For example, an eNB with PCI 1, whose peer has eNB ID `0x19c`, cell ID 1, and
address `192.0.2.22`:

```sh
SRSRAN_LAB_X2_PEER=192.0.2.22 \
SRSRAN_LAB_X2_PEER_ECI=0x19c01 \
SRSRAN_LAB_X2_PCI=1 \
SRSRAN_LAB_X2_EARFCN=3350 \
  ./build/enb-x2/srsenb/src/srsenb /path/to/enb.conf
```

Configure the other eNB with the reciprocal peer address and ECI, and its own
local PCI. The lower eNB ID initiates X2 Setup after S1 setup completes. Allow
SCTP/36422 between peers and the GTP-U forwarding traffic between their configured
GTP addresses.

Enable `ho_active` in the RRC cell configuration and configure the peer in
`meas_cell_list`, including its ECI, PCI, and EARFCN. Existing measurement-event
settings drive the handover decision. For encrypted testing, use:

```ini
[expert]
eea_pref_list = EEA2
eia_pref_list = EIA2
```

Leave `SRSRAN_LAB_X2_PEER` unset for S1 handover operation.

## FFTW startup option

`SRSRAN_LAB_FFTW_ESTIMATE=1` selects FFTW's `ESTIMATE` planner for DFT plans and
the Cedron frequency estimator. This reduces startup planning time in software
radio tests. The default remains `FFTW_MEASURE`.

```sh
SRSRAN_LAB_FFTW_ESTIMATE=1 ./build/enb-x2/srsue/src/srsue /path/to/ue.conf
```

## Testing

The native source changes match the patch tested in the
[srsRAN Mobility Lab](https://github.com/ripclap/srsran-mobility). Recorded
EEA2/EIA2 runs:

| Path | Handovers | Ping replies | UE session |
| --- | --- | --- | --- |
| X2 forward, reverse, outage recovery | 3 | 607/608 | IP preserved, no reattach |
| S1 forward and reverse | 2 | 229/230 | IP preserved, no reattach |

The X2 outage test blocks target SCTP output during preparation, checks source
and target timeout cleanup, restores the link, and completes another handover.
Captures were independently decoded to check X2 messages, IE criticalities,
Path Switch acknowledgements, and absence of S1 handover preparation in X2 mode.
See the lab's [test results](https://github.com/ripclap/srsran-mobility/blob/main/docs/testing.md).

## Supported profile

The current X2 implementation has one configured IPv4 peer and advertises a
single 6 PRB FDD cell on EARFCN 3350. The verified scenario uses two eNBs, one UE,
and a shared MME/SGW. SGW relocation and partial bearer admission are rejected.
Third-party X2 interoperability needs separate testing.
