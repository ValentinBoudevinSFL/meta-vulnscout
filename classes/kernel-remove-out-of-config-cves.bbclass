python do_clean:append() {
    import os, glob
    deploy_dir = d.expand('${DEPLOY_DIR_IMAGE}')
    for f in glob.glob(os.path.join(deploy_dir, '*kernel_removed_cves.json')):
        bb.note("Removing " + f)
        os.remove(f)
    for f in glob.glob(os.path.join(deploy_dir, '*kernel_remaining_cves.json')):
        bb.note("Removing " + f)
        os.remove(f)
    for f in glob.glob(os.path.join(deploy_dir, '*kernel_filtered.json')):
        bb.note("Removing " + f)
        os.remove(f)
}

do_kernel_filter() {
    # Define input files
    kernel_remove_out_of_config_cves_script="${COREBASE}/../meta-vulnscout/scripts/kernel_remove_out_of_config_cves.py"
    input_config_file="${B}/.config"
    input_cve_check="${WORKDIR}/temp/cve.json"
    vulns_path="${STAGING_DATADIR_NATIVE}/vulns-native"

    # Define output files
    new_kernel_remaining_cves_maps_file="${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_remaining_cves_map.json"

    # Check that the required files exist before running the script
    if [ ! -f "${input_cve_check}" ]; then
        bbwarn "Kernel_filter_cve: cve-check file not found: ${input_cve_check}"
        return 0
    fi
    if [ ! -f "${input_config_file}" ]; then
        bbwarn "Kernel_filter_cve: .config file not found: ${input_config_file}"
        return 0
    fi
    if [ ! -f "${kernel_remove_out_of_config_cves_script}" ]; then
        bbwarn "kernel_remove_out_of_config_cves_script: kernel_remove_out_of_config_cves_script.py script not found: ${kernel_remove_out_of_config_cves_script}"
        return 0
    fi
    if [ ! -d "${vulns_path}" ]; then
        bbwarn "Kernel_filter_cve: Vulnerabilities data not found in ${vulns_path}."
        return 0
    fi

    # Build the full command as a string (for debug)
    KERNEL_CVE_FILTER_CMD="python3 ${kernel_remove_out_of_config_cves_script} \
        --vulns-path ${vulns_path} \
        --input-cve-check ${input_cve_check} \
        --input-kernel-path ${STAGING_KERNEL_DIR} \
        --input-config-path ${input_config_file} \
        --output-filename-cve-check ${IMAGE_NAME}.kernel_filtered.json \
        --output-filename-remaining-cves ${IMAGE_NAME}.kernel_remaining_cves.json \
        --output-filename-removed-cves ${IMAGE_NAME}.kernel_removed_cves.json \
        --output-path ${DEPLOY_DIR_IMAGE}"

    # Debug: print the exact command that will be executed
    bbnote "Kernel CVE filter command:"
    bbnote "  ${KERNEL_CVE_FILTER_CMD}"

    # Launch the kernel filtering script
    ${KERNEL_CVE_FILTER_CMD}

    # Success message which returns the generated files
    bbplain "Remaining kernel CVEs mapping file: ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_remaining_cves.json"
    bbplain "Removed kernel CVEs not applicable to the current kernel configuration: ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_removed_cves.json"
    bbplain "New cve-check generated report with kernel cves filtered: ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_filtered.json"

    #Create a symlink as every other JSON file in tmp/deploy/images
    ln -sf ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_remaining_cves.json ${DEPLOY_DIR_IMAGE}/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}${IMAGE_NAME_SUFFIX}.kernel_remaining_cves.json
    ln -sf ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_removed_cves.json ${DEPLOY_DIR_IMAGE}/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}${IMAGE_NAME_SUFFIX}.kernel_removed_cves.json
    ln -sf ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_filtered.json ${DEPLOY_DIR_IMAGE}/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}${IMAGE_NAME_SUFFIX}.kernel_filtered.json
}
do_kernel_filter[depends] += "vulns-native:do_populate_sysroot"
do_kernel_filter[nostamp] = "1"
do_kernel_filter[doc] = "Run kernel_remove_out_of_config_cves.py with the current defconfig to filter out CVEs not applicable to the current kernel configuration and generate a new cve-check report and a mapping file of remaining kernel CVEs"
addtask kernel_filter after do_cve_check

# Add the do_kernel_filter task as a dependency of do_build to ensure it runs during the build process
do_build[depends] += "${PN}:do_kernel_filter"

# Task to re-run the kernel CVE filtering with the same input files but without re-running cve-check, useful for testing and debugging the kernel filtering script without having to re-run the entire cve-check process
python do_kernel_refilter() {
    bb.build.exec_func("do_kernel_filter",d)
}
do_kernel_refilter[depends] += "vulns-native:do_populate_sysroot"
do_kernel_refilter[nostamp] = "1"
do_kernel_refilter[doc] = "Run kernel_remove_out_of_config_cves.py with the current defconfig to filter out CVEs not applicable to the current kernel configuration and generate a new cve-check report and a mapping file of remaining kernel CVEs"
addtask kernel_refilter
