# VasDolly / Walle JAR interoperability baseline

The opt-in `interop` test suite uses external command line tools only. It does not add Java or either JAR to the runtime dependency graph.

| Tool | Version | SHA-256 |
| --- | --- | --- |
| VasDolly | 3.0.6 | `15364fd2d3725bed78d5bb4b00ce63b18e3a018438faf8fe030049099aa4da27` |
| Walle | 1.1.6 | `e655c5284ee1fc2916ccca2ed3217c4be227a8284fdb9218308c9cf431ef222c` |

Run with `-tags=interop` and set `VASDOLLY_JAR` and `WALLE_JAR`. The suite records MD5, length, and first byte differences. V1 output is byte-compared where both tools support the operation; modern Signing Block output is compared structurally because padding and Walle JSON serialization can differ.

Known tool limitations are explicit test cases: the VasDolly CLI cannot process V3-only/V3.1-only fixtures, Walle requires a V2 Signing Block and does not provide custom Block ID operations, and VasDolly's V1 CLI treats an empty channel read as an existing channel. These cases must not be interpreted as apktag failures. Walle's `show` command reports malformed JSON or invalid UTF-8 with its own parser behavior, while apktag rejects invalid payloads.
