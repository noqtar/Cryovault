# rimefold (coldpack) — CryoVault 2026

Category: Pwn · Solved by: Arjun Srikanth (CTFd: Arjun).

The challenge serves ABI 1.4 while the supplied local bench binary identifies as ABI 1.3. A record-classification and defragmentation issue leads to a memory alias into arena metadata. The successful live solve used the XOR callback strategy, and the recovered flag was accepted by CTFd.

The full source code was kept as a separate team file because GitHub rejected uploading the exploit via the connected integration. This directory contains documentation only; there is no source-code link here.

Technical approach, live verification output, and AI/tool disclosure are included in the team's qualifier writeup.
