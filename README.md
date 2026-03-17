# Rhombus: Fast Homomorphic Matrix-Vector Multiplication for Secure Two-Party Inference

This repository is developed based on [OpenCheetah](https://github.com/Alibaba-Gemini-Lab/OpenCheetah), and provides a proof-of-concept implementation of the paper [Rhombus](https://eprint.iacr.org/2024/1611.pdf). In summary, this project contains the following components:

- Tests for the protocols: matrix-vector multiplication, matrix-matrix multiplication in Rhombus
- End-to-end implementation of secure two-party inference of ResNet50 model

If you are more interested in the implementation of the algorithms in Rhombus, rather than its performance in secure two-party inference, we also provide a cleaner implementation [here](https://github.com/2646jx/Rhombus), which includes only the Rhombus algorithm itself, without any modules related to the network communication.

## Building

We prefer to compile on Linux OS, and we have successfully compiled it on Ubuntu by executing the following commands.

The build system supports two variants controlled by the `VARIANT` environment variable:

- `noavx512` (default) -- portable binaries without AVX-512 instructions
- `avx512` -- high-performance binaries with AVX-512 code paths for capable CPUs

### Building without AVX-512 (portable)

```bash
VARIANT=noavx512 bash scripts/build-deps.sh
VARIANT=noavx512 bash scripts/build.sh
```

Binaries are output to `build-noavx512/bin/`.

### Building with AVX-512

```bash
VARIANT=avx512 bash scripts/build-deps.sh
VARIANT=avx512 bash scripts/build.sh
```

Binaries are output to `build-avx512/bin/`.

Both variants can be built side by side -- they use separate build directories and share the same `deps/` source tree.

## Testing

Before performing the tests, execute the script file `scripts/throttle.sh` to mimic the network environment. For example,

Run the following command to mimic an LAN setting (3Gbps, 0.3ms):

```PowerShell
bash scripts/throttle.sh lan
```

Run the following command to mimic a WAN setting (100Mbps, 40ms):

```PowerShell
bash scripts/throttle.sh wan
```

Run the following command to remove the network traffic restriction:

```PowerShell
bash scripts/throttle.sh del
```

After setting the network environment, launch two terminals, representing the client and server, respectively.

### Module test

To test matrix-vector multiplication protocol, execute the following command in the client terminal:

```bash
./build-noavx512/bin/rhombus_matvec 2 12345
```

Correspondingly, execute the following command in the server terminal:

```bash
./build-noavx512/bin/rhombus_matvec 1 12345
```

The matrix-matrix multiplication protocol can be tested in a similar way as above.

In client terminal:

```bash
./build-noavx512/bin/rhombus_matmul 2 12345
```

In server terminal:

```bash
./build-noavx512/bin/rhombus_matmul 1 12345
```

Replace `build-noavx512` with `build-avx512` to use the AVX-512 variant.

After running the protocols successfully, the performance data will be printed. The total communication volume of the protocol is the sum of the client's and server's transmitted data. To configure the parameters of the protocol, e.g., the dimensions of the matrices, the number of threads, you can modify the parameters in the  corresponding files, then recompile them.

### End-to-end test for ResNet50

To run [Cheetah](https://eprint.iacr.org/2022/207.pdf), execute the following command in client terminal:

```PowerShell
bash scripts/run-client.sh cheetah resnet50
```

In the server terminal, execute:

```PowerShell
bash scripts/run-server.sh cheetah resnet50
```

To run [Rhombus](https://eprint.iacr.org/2024/1611.pdf), you can directly change the `cheetah` by `rhombus` in the above commands. In particular, run this
command in client terminal:

```PowerShell
bash scripts/run-client.sh rhombus resnet50
```

In server terminal, run:

```PowerShell
bash scripts/run-server.sh rhombus resnet50
```

After running the two programs, the performance results will be printed in the server's terminal.

## LICENSE

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
