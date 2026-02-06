KERNEL_FILTER_CVE_PATH="${TMPDIR}/work/${MULTIMACH_TARGET_SYS}/kernel-filter-cve"

python do_clean:append() {
    import os, glob
    deploy_dir = d.expand('${DEPLOY_DIR_IMAGE}')
    for f in glob.glob(os.path.join(deploy_dir, '*kernel_filtered.json')):
        bb.note("Removing " + f)
        os.remove(f)
    for f in glob.glob(os.path.join(deploy_dir, '*kernel_remaining_cves_map.json')):
        bb.note("Removing " + f)
        os.remove(f)
}

do_kernel_remove_out_of_config_cves() {
    # Define input files
    original_cve_check_file="${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.json"
    kernel_remove_out_of_config_cves_script="${COREBASE}/../meta-vulnscout/scripts/kernel_remove_out_of_config_cves.py"
    input_config_file="${KERNEL_FILTER_CVE_PATH}/defconfig"

    # Define output files
    new_cve_report_file="${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_filtered.json"
    new_kernel_remaining_cves_maps_file="${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_remaining_cves_map.json"

    # Check that the required files exist before running the script
    if [ ! -f "${original_cve_check_file}" ]; then
        bbwarn "Kernel_filter_cve: cve-check file not found: ${original_cve_check_file}"
        return 0
    fi

    if [ ! -f "${kernel_filter_cve_config_file}" ]; then
        bbwarn "Kernel_filter_cve: .config file not found: ${kernel_filter_cve_config_file}"
        return 0
    fi

    if [ ! -f "${kernel_remove_out_of_config_cves_script}" ]; then
        bbwarn "kernel_remove_out_of_config_cves_script: kernel_remove_out_of_config_cves_script.py script not found: ${kernel_remove_out_of_config_cves_script}"
        return 0
    fi

    #Launch the kernel filtering script
    python3 "${kernel_remove_out_of_config_cves_script}" \
        --vulns-path "${TODO}" \
        --input-cve-check "${original_cve_check_file}" \
        --input-kernel-path "${STAGING_KERNEL_DIR}" \
        --input-config-path "${TODO}" \
        --output-files-name "${IMAGE_LINK_NAME}" \
        --output-path "${DEPLOY_DIR_IMAGE}" \
    ret=$?

    # Check the return code of the script
    if [ $ret -ne 0 ]; then
        bbfatal "Kernel CVE filtering failed (exit code $ret):\n${output}"
    fi

    # Success message
    bbplain "Kernel CVE filtering completed successfully"
    bbplain "New cve-check generated report with kernel cves filtered: ${new_cve_report_file}"

    #Create a symlink as every other JSON file in tmp/deploy/images
    ln -sf ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_remaining_cves_map.json ${DEPLOY_DIR_IMAGE}/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}${IMAGE_NAME_SUFFIX}.kernel_remaining_cves_map.json
    ln -sf ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_filtered.json ${DEPLOY_DIR_IMAGE}/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}${IMAGE_NAME_SUFFIX}.kernel_filtered.json
}
do_kernel_remove_out_of_config_cves[depends] += "vulns-native:do_populate_sysroot"
do_kernel_remove_out_of_config_cves[nostamp] = "1"
do_kernel_remove_out_of_config_cves[doc] = "Run kernel_remove_out_of_config_cves.py with the current defconfig to filter out CVEs not applicable to the current kernel configuration and generate a new cve-check report and a mapping file of remaining kernel CVEs"
addtask kernel_remove_out_of_config_cves after do_image_complete