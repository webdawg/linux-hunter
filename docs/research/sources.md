# Sources

Research compiled 2026-10-18. Entries for Ebury, xz-utils, Drovorub, XorDDoS history, and
classic LKM rootkits draw also on well-established public reporting; verify against vendor
write-ups before turning them into rules.

## Overviews and detection engineering
- Elastic Security Labs — Linux Detection Engineering: A primer on persistence mechanisms (introduces PANIX): https://www.elastic.co/security-labs/primer-on-persistence-mechanisms
- Elastic Security Labs — A Continuation on Persistence Mechanisms: https://www.elastic.co/security-labs/continuation-on-persistence-mechanisms
- Elastic Security Labs — A Sequel on Persistence Mechanisms: https://www.elastic.co/security-labs/threat-command/sequel-on-persistence-mechanisms
- Elastic Security Labs — Hooked on Linux: Rootkit Taxonomy, Hooking Techniques and Tradecraft: https://www.elastic.co/security-labs/linux-rootkits-1-hooked-on-linux
- Elastic Security Labs — Hooked on Linux: Rootkit Detection Engineering: https://www.elastic.co/security-labs/threat-command/linux-rootkits-2-caught-in-the-act
- Karneades — malware-persistence collection: https://github.com/Karneades/malware-persistence
- awesome-linux-rootkits list: https://github.com/dukebarman/awesome-linux-rootkits
- Cron persistence guide (XorDDoS, Kaiji examples): https://ostechnix.com/cron-persistence-linux-malware/

## eBPF / io_uring / telemetry evasion
- BleepingComputer — io_uring blindspot / Curing: https://www.bleepingcomputer.com/news/security/linux-io-uring-security-blindspot-allows-stealthy-rootkit-attacks/
- Security Affairs — Curing evades Falco/Tetragon: https://securityaffairs.com/177098/hacking/poc-rootkit-curing-evades-traditional-linux-detection-systems.html
- memf-linux io_uring forensics module docs: https://docs.rs/memf-linux/latest/memf_linux/io_uring/
- LinuxSecurity — eBPF monitoring vs rootkit evasion (SPiCa): https://linuxsecurity.com/features/ebpf-security-tools-rootkit-evasion
- Cybersecurity News — eBPF and io_uring rootkits: https://cybersecuritynews.com/linux-rootkits-using-advanced-ebpf/

## Malware families
- Sophos via BleepingComputer — PoisonedRefresh on F5 BIG-IP (Sep 2026): https://bleepingcomputer.com/news/security/hackers-breach-f5-big-ip-apm-devices-to-deploy-linux-rootkit
- Security Affairs — PoisonedRefresh details: https://securityaffairs.com/198746/malware/poisonedrefresh-a-fileless-linux-rootkit-that-injects-php-web-shells-into-f5-big-ip-apm-server-memory.html
- Acronis TRU — Red Heron / SIXZUT rootkit: https://www.acronis.com/en/tru/posts/red-heron-exploits-gitea-n-day-flaw-in-multinational-campaign-exposing-new-linux-rootkit/
- BleepingComputer — 400+ AUR packages push rootkit/infostealer: https://www.bleepingcomputer.com/news/security/over-400-arch-linux-packages-compromised-to-push-rootkit-infostealer/
- Trend Micro — Quasar Linux (QLNX): https://trendmicro.com/en_us/research/26/e/quasar-linux-qlnx-a-silent-foothold-in-the-software-supply-chain.html
- BleepingComputer — QLNX seven persistence mechanisms: https://www.bleepingcomputer.com/news/security/new-stealthy-quasar-linux-malware-targets-software-developers/amp/
- Security Affairs — QLNX: https://securityaffairs.com/191898/malware/quasar-linux-rat-qlnx-a-fileless-linux-implant-built-for-stealth-and-persistence.html
- The Hacker News — VoidLink: https://thehackernews.com/2026/01/new-advanced-linux-voidlink-malware.html
- Sysdig — VoidLink C2-compiled kernel rootkits: https://www.sysdig.com/blog/voidlink-threat-analysis-sysdig-discovers-c2-compiled-kernel-rootkits
- Elastic — Illuminating VoidLink: https://www.elastic.co/security-labs/illuminating-voidlink
- Synacktiv — LinkPro eBPF rootkit analysis: https://synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis
- The Hacker News — LinkPro: https://thehackernews.com/2025/10/linkpro-linux-rootkit-uses-ebpf-to-hide.html
- Wiz threat landscape — LinkPro campaign: https://threats.wiz.io/all-incidents/ebpf-rootkit-targeting-aws-and-linux-environments
- Singularity rootkit (GitHub): https://github.com/MatheuZSecurity/Singularity
- LWN — A free and open-source rootkit for Linux (Singularity): https://lwn.net/Articles/1054411/
- Security Affairs — Plague PAM backdoor (Nextron Systems research): https://securityaffairs.com/180701/malware/new-linux-backdoor-plague-bypasses-auth-via-malicious-pam-module.html
- CyberArk — Plague and prior PAM abuse (Orbit, Azazel, Skidmap): https://www.cyberark.com/resources/threat-research/plague-malware-exploits-pluggable-authentication-module-to-breach-linux-systems
- Field Effect — Auto-color: https://fieldeffect.com/blog/new-auto-color-backdoor-serious-threat-to-linux-systems
- Darktrace — Auto-color via SAP CVE-2025-31324: https://www.darktrace.com/blog/auto-color-backdoor-how-darktrace-thwarted-a-stealthy-linux-intrusion
- Security Affairs — PUMAKIT (Elastic research): https://securityaffairs.com/172016/uncategorized/pumakit-sophisticated-rootkit.html
- The Hacker News — PUMAKIT: https://thehackernews.com/2024/12/new-linux-rootkit-pumakit-uses-advanced.html
- Aqua Security — perfctl: https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/
- Wiz — perfctl summary: https://threats.wiz.io/all-incidents/perfctl-malware-targeting-linux
- Security Affairs — perfctl persistence details: https://securityaffairs.com/169351/malware/perfctl-malware-targets-misconfigured-linux-servers.html
- Aon / Stroz Friedberg — sedexp udev persistence: https://aon.com/en/insights/cyber-labs/unveiling-sedexp
- BleepingComputer — sedexp: https://www.bleepingcomputer.com/news/security/stealthy-sedexp-linux-malware-evaded-detection-for-two-years/
- Intezer — Symbiote: https://research.intezer.com/blog/2022/06/new-linux-threat-symbiote/
- Trend Micro — BPFDoor variants: https://www.trendmicro.com/en_us/research/23/g/detecting-bpfdoor-backdoor-variants-abusing-bpf-filters.html
- haxrob — BPFDoor part 2 (2025 telecom samples): https://haxrob.net/tag/bpfdoor/
- SOC Prime summary of Rapid7 BPFDoor variants white paper: https://socprime.com/fr/active-threats/livre-blanc-discret-bpfdoor/
- IMDA Singapore — Earth Bluecrow / BPFDoor advisory: https://www.imda.gov.sg/-/media/imda/files/regulations-and-licensing/regulations/advisories/infocomm-media-cyber-security/earth-bluecrow-deploys-bpfdoor-malware-across-telcos-in-asia.pdf
- Wikipedia — XorDDoS: https://en.wikipedia.org/wiki/Xor_DDoS
- Wikipedia — Gayfemboy: https://en.wikipedia.org/wiki/Gayfemboy
