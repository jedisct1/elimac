# EliMac

EliMac is a ridiculously fast AES-based Message Authentication Code.

It was designed by Christoph Dobraunig, Bart Mennink and Samuel Neves, and was presented at FSE 2024.

This is an experimental implementation for ARM64 CPUs with AES extensions, leveraging precomputation.

Untested, do not use for anything serious.

## Benchmark (Macbook Pro M1)

| Name            | Speed          |
| --------------- | -------------- |
| AEGIS-128L MAC  | 126404.87 Mb/s |
| AEGIS-128X2 MAC | 166600.71 Mb/s |
| EliMAC          | 247316.74 Mb/s |