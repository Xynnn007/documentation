# Use CC KBC and generic KBS (TDX)

[CC KBC](https://github.com/confidential-containers/attestation-agent/tree/main/src/kbc_modules/cc_kbc) and [generic KBS](https://github.com/confidential-containers/kbs) are a KBC-KBS pair designed and maintained by CoCo Community. The two componants communicates with each other on the [KBS Attestation Protocol](https://github.com/confidential-containers/kbs/blob/main/docs/kbs_attestation_protocol.md).

## Basic Workflow

### Deploy tenant-side Cluster and Generate Encrypted Image

A tenant-side cluster includes:
- Key Broker Service (KBS): Brokering service for confidential resources.
- Attestation Service (AS): Verifier for remote attestation.
- Reference Value Provicer Service (RVPS): Provides reference values for AS.
- CoCo Keyprovider: Component to encrypt the images following ocicrypt spec.

To quick start the cluster, a `docker-compose` yaml is provided to launch.

```shell
git clone https://github.com/confidential-containers/kbs.git

cd kbs

docker-compose up -d
```

Then the cluster will be launch. More information please refer to [this document](https://github.com/confidential-containers/kbs/blob/main/docs/cluster.md).

### Deploy the Encrypted Image

First we need 

## Advanced Features

### Given Reference Values for Remote Attestation

By default, we does not verify the `kernel commandline`, `kernel`, etc. However, we provides a way to specify the allowlist of the reference values of the following:
- `tdx-tcb-svn` : `tcb_svn` field inside the `report_body` of the quote.
- `tdx-mrseam`: `mr_seam` field inside the `report_body` of the quote.
- `tdx-mrtd`: `mr_td` field inside `report_body` of the quote, which implies the guest firmware.
- `tdx-mrconfigid`: `mr_config_id` field inside `report_body` of the quote.
- `tdx-kernel-size{:?}`: measurement of the guest kernel and the total length of the measured memory content is specified by `{:?}`.

We can use a client to inject the reference values into `RVPS`. When the remote attestation occurs, the AS will query the reference values from RVPS.

For example we'd use reference value for guest kernel, we first prepare a JSON file e.g. `./message` like the following format 

```json
{
    "tdx-kernel-size0x10000000": [
        "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
        "2aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba7"
    ]
}
```

Suppose we've already launched the KBS cluster, and the port mapped on the host of RVPS is `50003`.
Use the RVPS client
```shell
git clone https://github.com/confidential-containers/attestation-service.git
cd attestation-service/tools/rvps-client

cargo run -- register --path ./message --addr http://127.0.0.1:50003
```

Then the reference values of kernel of 0x10000000 bytes will be registered.

### Configure the OPA for Remote Attestation

