# Optional: add kernel-generate-cve-exclusions class to generate CVE exclusion files for the kernel
inherit kernel-generate-cve-exclusions

# Optional: add kernel_remove_out_of_config_cves class to filter out CVEs not applicable to the current kernel defconfig
inherit kernel_remove_out_of_config_cves