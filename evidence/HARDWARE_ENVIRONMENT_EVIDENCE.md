# Hardware/OS Environment Evidence

Resolves the previously-reported "CPU/RAM/GPU not available" gap in the Reproducibility table and
in `REPRODUCIBILITY_GAPS.md` ("Scanner execution environment (container image, OS, hardware):
NOT AVAILABLE").

## Evidence supplied by the author

A Windows Device Info / System screen, showing the specifications of the experimental machine.

## Recorded specifications

| Item | Value |
|---|---|
| OS | Windows 11 Education, version 25H2, OS build 26200.9278 |
| System type | 64-bit operating system, x64-based processor |
| Processor | Intel Core Ultra 7 155H, 1.40 GHz |
| Installed RAM | 16 GB (15.5 GB usable) |
| GPU | NVIDIA RTX 500 Ada Generation Laptop GPU (4 GB), with integrated Intel Graphics |

**Deliberately not recorded:** the screenshot's Device ID and Product ID. These are
machine-identifying values with no reproducibility value (they don't affect how the ontology
parses, how HermiT reasons, or how the SWRL materialization runs) and are excluded per explicit
author instruction to avoid unnecessarily publishing machine-identifying information.

## Scope of this evidence

This documents the hardware of the machine used for this project's environment (the same machine
already established, via the earlier HermiT/Protégé evidence, as the host for the HermiT
consistency check). It is reported honestly as informational reproducibility context — consistent
with the existing caveat in `REVISION2_REPRODUCIBILITY_PROTOCOL.md` that the parse-time/memory
figures are a loadability data point, not a production-system performance benchmark, and are not
claimed to characterize any different original-construction environment.

## Manuscript location updated

`RiskOnto_Revision2.tex`, Reproducibility table (`tab:reproducibility`), "OS/hardware" row: the
previous "CPU/RAM/GPU not available in accessible project evidence and not fabricated" wording is
replaced with the specifications above.
