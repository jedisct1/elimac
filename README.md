# EliMAC

EliMAC is a ridiculously fast AES-based Message Authentication Code.

It was designed by Christoph Dobraunig, Bart Mennink and Samuel Neves, and was presented at FSE 2024.

This is an experimental implementation for x86_64 and ARM64 CPUs with AES extensions, leveraging precomputation.

Untested, do not use for anything serious.

## Benchmark (Macbook Pro M1)

| Name            | Speed       |
| --------------- | ----------- |
| AEGIS-128X2 MAC | 166600 Mb/s |
| EliMAC          | 247316 Mb/s |

## Benchmark (Zen 4)

| Name            | Speed       |
| --------------- | ----------- |
| AEGIS-128X4 MAC | 396880 Mb/s |
| EliMAC          | 452163 Mb/s |
