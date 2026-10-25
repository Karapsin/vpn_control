"""Exercise Git's Windows line-ending conversion on exact historical fixtures."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = (
    ("agent_tools/tests/fixtures/windows_cp117_recovery/short_socket_51538dad.source",
     "51538dad4c2fa6591384081f5a0aabacada1e752c1afd6a6ed50ebed9596663e"),
    ("agent_tools/tests/fixtures/android_proxy_os_history/retirement_3eed5a2e.source",
     "3eed5a2ecf544ab306e79847152145e1d78112bd5f40ec00f66a8638e0c40f7c"),
    ("agent_tools/tests/fixtures/android_component_legacy/provenance.json",
     "c4c4afe5b101f099f23bc80cc8dfb7e1d3febff7299ee53672128a0440806742"),
    ("agent_tools/tests/fixtures/windows_readiness_workflow_before/windows-desktop.yml",
     "54229369500fd95d9935876fb9aac887362f55df2eeee9f6fb2f22a5f9f42d57"),
)
RAW_PROVENANCE_FAMILIES = (
    ("agent_tools/tests/fixtures/windows_jobs_reflection", "provenance.json", ("sourceSha256",)),
    ("agent_tools/tests/fixtures/android_adb_jobs", "sdk_harness.provenance.json",
     ("sourceSha256", "receiptSha256")),
)
PINNED_FAMILIES = (
    "scripts/testdata/windows-persistent-ready-parser",
    "scripts/testdata/windows-persistent-taskroot",
)


# Complete pre-enrollment attributes, retained inline because this byte-custody
# test is itself protected by the existing Python -text policy.
DEPENDENCY_ATTRIBUTES_BEFORE = (
    b'visual-tests/baselines/**/*.png filter=lfs diff=lfs merge=lfs -text\n'
    b'\n'
    b'# These reviewed inputs are hashed byte-for-byte into native helper manifests.\n'
    b'/desktopApp/native/windows/import-policy.json text eol=lf\n'
    b'/desktopApp/native/windows/InstallHelper/loader.manifest text eol=lf\n'
    b'/desktopApp/native/windows/VpnBroker/loader.manifest text eol=lf\n'
    b'\n'
    b'# Tool loaders and their preserved Python beforeimages authenticate exact bytes.\n'
    b'# Keep Git blobs intact when Windows enables automatic line-ending conversion.\n'
    b'/agent_tools/**/*.py -text\n'
    b'/agent_tools/ssh_source_file_gateway.source -text\n'
    b'\n'
    b'# Historical source fixtures retain the exact bytes named by their provenance.\n'
    b'/agent_tools/tests/fixtures/**/*.source -text\n'
    b'/agent_tools/tests/fixtures/native_wire_event_evidence/*.fragment -text\n'
    b'/agent_tools/tests/fixtures/windows_cp117_publisher_boundary/*.fragment -text\n'
    b'/agent_tools/tests/fixtures/fast_workflow_budget/before.yml -text\n'
    b'/agent_tools/tests/fixtures/fast_workflow_interpreter_order/*.yml -text\n'
    b'/agent_tools/tests/fixtures/agent_ci_shards/*.yml -text\n'
    b'/agent_tools/tests/fixtures/windows_readiness_workflow_before/*.yml -text\n'
    b'/agent_tools/tests/fixtures/msi_qga_fixture_bounds/*.fragment -text\n'
    b'/agent_tools/tests/fixtures/android_component_legacy/provenance.json text eol=lf\n'
    b'\n'
    b'# Frozen persistent-task fixtures retain their manifest-pinned source bytes.\n'
    b'/scripts/testdata/windows-persistent-ready-parser/** -text\n'
    b'/scripts/testdata/windows-persistent-taskroot/** -text\n'
    b'\n'
    b'# The monitor regression authenticates its exact retained timeout assertion.\n'
    b'/scripts/test_macos_vm_resource_monitor.py -text\n'
    b'/scripts/testdata/macos-vm-resource-monitor-dispatch/*.fragment -text\n'
    b'\n'
    b'/agent_tools/tests/fixtures/setup_process_capture/*.ps1 -text\n'
    b'\n'
    b'/agent_tools/tests/fixtures/setup_child_exit/*.ps1 -text\n'
    b'/agent_tools/tests/fixtures/setup_msi_phase/*.ps1 -text\n'
    b'\n'
    b'agent_tools/tests/fixtures/windows_standard_token/*.ps1 -text\n'
    b'\n'
    b'# These Windows causal readers authenticate raw specimen and manifest bytes.\n'
    b'/agent_tools/tests/fixtures/windows_ordinary_https/prior-direct-tls.cs -text\n'
    b'/agent_tools/tests/fixtures/windows_ordinary_https/before-total-deadline.cs -text\n'
    b'/agent_tools/tests/fixtures/windows_secondary_cleanup/provenance.json -text\n'
    b'/agent_tools/tests/fixtures/windows_secondary_cleanup/legacy_file_binding.ps1 -text\n'
    b'/agent_tools/tests/fixtures/windows_secondary_cleanup/current_file_binding.ps1 -text\n'
    b'/agent_tools/tests/fixtures/windows_secondary_cleanup/reader_handles.ps1 -text\n'
    b'/agent_tools/tests/fixtures/windows_secondary_cleanup/delete_native.cs -text\n'
    b'/agent_tools/tests/fixtures/windows_fixture_checkout_bytes/attributes.before -text\n'
    b'/agent_tools/tests/fixtures/windows_complete_program_transfer/provenance.json -text\n'
    b'/agent_tools/tests/fixtures/windows_complete_program_transfer/decoder.before.fragment -text\n'
    b'/agent_tools/tests/fixtures/windows_complete_program_transfer/haderrors.before.fragment -text\n'
    b'/agent_tools/tests/fixtures/cp117_fixture_context_portability/geometry-imports.before.fragment -text\n'
    b'/agent_tools/tests/fixtures/cp117_fixture_context_portability/windowless-imports.before.fragment -text\n'
    b'/agent_tools/tests/fixtures/whole_observer_binary/fixture.before.fragment -text\n'
    b'/agent_tools/tests/fixtures/qemu_projection_birth/projection.before.fragment -text\n'
    b'/agent_tools/tests/fixtures/native_engineering_bytecode_cache/entrypoint.before.source -text\n'
    b'/agent_tools/tests/fixtures/native_engineering_bytecode_cache/provenance.json -text\n'
    b'/agent_tools/tests/fixtures/windows_cp117_fixture_transport_prerequisites/provenance.json -text\n'
    b'/agent_tools/tests/fixtures/windows_cp117_catalogue_path_context/before.fragment -text\n'
    b'/agent_tools/tests/fixtures/windows_cp117_catalogue_path_context/catalogue-fragment.before.ps1 -text\n'
    b'/scripts/windows_fixture_stage_acl.py -text\n'
    b'/agent_tools/tests/fixtures/windows_cp117_stage_checkout/attributes.before -text\n'
    b'/agent_tools/tests/fixtures/windows_powershell_environment/native_module_script_c.before.ps1 -text\n'
    b'/scripts/windows_task_admission.ps1 -text\n'
    b'/scripts/windows_credential_validity_qga.py -text\n'
    b'/agent_tools/tests/fixtures/windows_powershell_environment/native_capture_document_ca1.before.fragment -text\n'
    b'/agent_tools/tests/fixtures/windows_shortcut_task_marker/provenance.json -text\n'
    b'/agent_tools/tests/fixtures/linux_native_cleanup_enrollment/linux-desktop.before.yml -text\n'
    b'\n'
    b'# Native provider/parser causal fixtures authenticate exact Git payload bytes.\n'
    b'/agent_tools/tests/fixtures/windows_powershell_environment/native_module_g.before.ps1 -text\n'
    b'/agent_tools/tests/fixtures/windows_powershell_environment/native_g_document.before.fragment -text\n'
    b'/agent_tools/tests/fixtures/windows_manifest_parser/native-v3.before.ps1 -text\n'
    b'/agent_tools/tests/fixtures/windows_manifest_parser/Utility.literal.before.psd1 -text\n'
    b'\n'
    b'# The late-ready causal regression authenticates the complete original source.\n'
    b'/agent_tools/tests/fixtures/ssh_late_ready_handshake/ready.before.source -text\n'
    b'/agent_tools/tests/fixtures/windows_powershell_environment/native_module_i.before.ps1 -text\n'
    b'/agent_tools/tests/fixtures/windows_powershell_environment/native_provider_custody.ps1 -text\n'
    b'\n'
    b'# Recovery native receipts and ABI fixtures authenticate exact preserved bytes.\n'
    b'/agent_tools/tests/fixtures/windows_jobs_reflection/** -text\n'
    b'/agent_tools/tests/fixtures/android_adb_jobs/sdk*.json -text\n'
    b'/agent_tools/tests/fixtures/windows_token_restore_probe.ps1 -text\n'
    b'/agent_tools/tests/fixtures/recovery_fixture_checkout_bytes/attributes.before -text\n'
    b'/agent_tools/tests/fixtures/explicit_android_reset_target/** -text\n'
    b'/agent_tools/tests/fixtures/windows_jobs_observer_framing/** -text\n'
    b'/agent_tools/tests/fixtures/windows_jobs_default_owner/** -text\n'
    b'/agent_tools/tests/fixtures/windows_desktop_background_roles/** -text\n'
    b'/scripts/tests/fixtures/visual_target_before/** -text\n'
    b'/agent_tools/tests/fixtures/recovery_checkout_extended/attributes.before -text\n'
    b'/agent_tools/tests/fixtures/windows_job_ack_guidance/** -text\n'
    b'/agent_tools/tests/fixtures/resource_running_actor_before/public-measurement.json -text\n'
    b'/agent_tools/tests/fixtures/windows_jobs_preexec/** -text\n'
    b'/agent_tools/tests/fixtures/windows_defender_installed_service/native-before.json -text\n'
    b'/agent_tools/tests/fixtures/tart_virtiofs_python_copy/** -text\n'
)
DEPENDENCY_BYTE_FIXTURES = (
    ('agent_tools/tests/fixtures/native_preflight_run_boundary/native-failure.txt',
     'fad3f7676158685824c2be4fba8e863927e7088fdc3ad6e87c3d6d9ddcb9f12e', None),
    ('agent_tools/tests/fixtures/native_preflight_run_boundary/provenance.json',
     'ead04ce3cd08114c486c6b337b48d97be4c4d193bb7fc5f3a28d8af9621fed76', None),
    ('agent_tools/tests/fixtures/ssh_direct_inventory_epoch/native-errors.txt',
     'b97bda4f2c07a328c8b2bc6a0fa8168e61a088f52e7c557bd5ce3ef769cbbc9c', None),
    ('agent_tools/tests/fixtures/ssh_direct_inventory_epoch/provenance.json',
     '60a65413629b03c92b57094f259b0c364359a97a4efc53b92bbba1646d24ad83', None),
    ('agent_tools/tests/fixtures/readiness_portable_import/original-failure.log',
     'f93ccac1c8e5b30fd516ca0da0de37ee19dc8edf8c3172462520a81e7e37f65b', None),
    ('agent_tools/tests/fixtures/readiness_portable_import/provenance.json',
     'e191574caacfdc5a89a4f7a9e8a5c4424bec8038e1389aa23b7f8c8554fec157', None),
    ('agent_tools/tests/fixtures/inventory_fd_baseline/native-failure.txt',
     '80e78173c3cc28159a1e8606a0e6189c63a09fd69aa17e8c1be7f51445609255', None),
    ('agent_tools/tests/fixtures/inventory_fd_baseline/provenance.json',
     '0873aa50a0309fab9db335d46f8749467a0cb9fbc2129b8ce59f0749de4b41e2', None),
    ('agent_tools/tests/fixtures/ssh_direct_ended_v1/reviewed_optimizer/provenance.json',
     '36be70baabf05dd6378a9cda0a534d0e6ad1a609881977d656fa5758fa1bbb52', None),
    ('agent_tools/tests/fixtures/tmux_private_reply_projection/provenance.json',
     'e251d91369a82768abbeb8474fe3503184ea9689b756ee510801a2658b783f6c', None),
)

# Exact subsequent attributes epoch before enrolling the two new receipts.
ENROLLMENT_ATTRIBUTES_BEFORE = DEPENDENCY_ATTRIBUTES_BEFORE + (
    b'\n'
    b'# Authenticated infrastructure evidence retains original Git payload bytes.\n'
    b'/agent_tools/tests/fixtures/native_preflight_run_boundary/** -text\n'
    b'/agent_tools/tests/fixtures/ssh_direct_inventory_epoch/** -text\n'
    b'/agent_tools/tests/fixtures/ssh_direct_ended_v1/reviewed_optimizer/provenance.json -text\n'
    b'/agent_tools/tests/fixtures/readiness_portable_import/** -text\n'
    b'/agent_tools/tests/fixtures/inventory_fd_baseline/** -text\n'
    b'/agent_tools/tests/fixtures/tmux_private_reply_projection/provenance.json -text\n'
)
ENROLLMENT_BYTE_FIXTURES = (
    ('agent_tools/tests/fixtures/linux_tpm_native_enrollment/provenance.json',
     '9e57c47c294caa46b4dba4fbe07a38d48ee6cf55f36c8285b22b06f9c41406ea', None),
    ('agent_tools/tests/fixtures/credential_capture_retention/provenance.json',
     'f46c35eff69a7ef1fc403b25c421210b0d30c0daa6f31cd64a85cdaa3e64d89d', None),
)

# Complete byte-policy epoch before the three closed recovery families.
CLOSED_FAMILY_ATTRIBUTES_BEFORE = ENROLLMENT_ATTRIBUTES_BEFORE + (
    b'/agent_tools/tests/fixtures/linux_tpm_native_enrollment/provenance.json -text\n'
    b'/agent_tools/tests/fixtures/credential_capture_retention/provenance.json -text\n'
)
CLOSED_FAMILY_BYTE_FIXTURES = (
    ('agent_tools/tests/fixtures/ssh_adapter_context/native-failures.txt',
     '8a749621cb28f63bf570ccf7e4cf41e4795588613e2d6c85893ee9baabb2c2ef', None),
    ('agent_tools/tests/fixtures/ssh_adapter_context/provenance.json',
     '7d284ae1d509304cc57924a9b1a5ed4119e09ab4c0e9297c516f439c4eb1862e', None),
    ('agent_tools/tests/fixtures/ssh_unit_readiness/native-failures.txt',
     'fd488ab0e133b0bcddd98b619e121be59bd9c88bb4e5d58fcad035084b4a792e', None),
    ('agent_tools/tests/fixtures/ssh_unit_readiness/provenance.json',
     'df2c027e9ce0f6bc30333e4443f8664ff38efa3924c29f1eff33ff7c42f0389d', None),
    ('agent_tools/tests/fixtures/windows_host_work_acceptance/actual-failure.txt',
     '42d226d696154a1e6993f1ecab68cfa60f9c55a59054e66dc7defc5d85a3cffc', None),
    ('agent_tools/tests/fixtures/windows_host_work_acceptance/provenance.json',
     '1d3721a8a420d84d8b9a128e4c886fdf04fece272c0263c29a0bcdb157226333', None),
)

# Complete preceding policy; scripts beforeimages require their own finite rule.
SCRIPT_SEAM_ATTRIBUTES_BEFORE = CLOSED_FAMILY_ATTRIBUTES_BEFORE + (
    b'/agent_tools/tests/fixtures/ssh_adapter_context/** -text\n'
    b'/agent_tools/tests/fixtures/ssh_unit_readiness/** -text\n'
    b'/agent_tools/tests/fixtures/windows_host_work_acceptance/** -text\n'
)
SCRIPT_SEAM_BYTE_FIXTURES = (
    ('scripts/tests/fixtures/readiness_test_seams/actual-failures.txt',
     'a189318103df86d14ba46fe316d40a5b9d9d50ece188e7ac68935e63a688e9bb', None),
    ('scripts/tests/fixtures/readiness_test_seams/provenance.json',
     'c3ab66979befefd49f7e9600d9653d4e0c1277c17964789a96e925a1770b06af', None),
    ('scripts/tests/fixtures/readiness_test_seams/test_android_installer_lifecycle.py.before.source',
     '87dbb6ba70c2d6442d9acbbe42a19efc8f28b5d1e4a00ab7951d0d7bb3be25c7', None),
    ('scripts/tests/fixtures/readiness_test_seams/test_native_jvm_tests.py.before.source',
     'b498893e6524372677fa904bdb2f15d422d78b911280aa5908f6fb478977b51e', None),
)

# Full preceding policy before original Windows host-phase receipt enrollment.
HOST_PHASE_ATTRIBUTES_BEFORE = SCRIPT_SEAM_ATTRIBUTES_BEFORE + (
    b'/scripts/tests/fixtures/readiness_test_seams/** -text\n'
)
HOST_PHASE_BYTE_FIXTURES = (
    ('agent_tools/tests/fixtures/windows_host_phase_integration/endpoint-native-failure.json',
     '8f8a7f81ee6ea75e79bdb192ca4ec3f3be2b9bbc4fab199e237b99fad4a00c77', None),
    ('agent_tools/tests/fixtures/windows_host_phase_integration/native-before.json',
     '74fdbfd53ba70ca80854e5c527f7b5ed4f32322e17a0489b945ee47c12adc3b5', None),
    ('agent_tools/tests/fixtures/windows_host_phase_integration/provenance.json',
     '2d0035fc34522941a1ac167bfa2cceb8fd72339537113302e661978146476542', None),
    ('agent_tools/tests/fixtures/windows_host_work/define.capture.json',
     'fdfe2da870de6f1b57fec354473cecbe80d8873a0e266d78ae0ced8c4b1a0847', None),
    ('agent_tools/tests/fixtures/windows_host_work/define.closing.json',
     '7329107b2b8e6de58a2a06e25afcc2683ec7fcbc51aaf4b3f3028a8a75f7f551', None),
    ('agent_tools/tests/fixtures/windows_host_work/documents.callback.json',
     '0aeb76bd2408d1d5b94cfd159deb5197c44eb3f9f0acbd6fdbdd0d637752ec4b', None),
    ('agent_tools/tests/fixtures/windows_host_work/documents.result.json',
     '21224eabd44969681155b5cb0928c2db9f303a99f5cf3f7c3f23bddcacc04868', None),
    ('agent_tools/tests/fixtures/windows_host_work/native-failure.json',
     '7be6fb9f4d4c8ae9621bf796ed26e84f44c473da09269e1d43cae1f3001c92f8', None),
    ('agent_tools/tests/fixtures/windows_host_work/provenance.json',
     '3c2fc307b7ea7770e7a255120ee13df91f0eef54fe0182173ec64119bc059a42', None),
    ('agent_tools/tests/fixtures/windows_host_work/start.capture.json',
     'a7f1f0c6d78fdfca3dbade6687de11fe9c35b55f9f883dae10673b31bd3e03e0', None),
    ('agent_tools/tests/fixtures/windows_host_work/start.closing.json',
     '491714e8e0f0dca73cf50a330b60121e981422d65396e43d761d1177bd9e5a09', None),
)

# Whole policy before enrolling the reviewed pre-credential/public frames.
PUBLIC_FRAME_ATTRIBUTES_BEFORE = HOST_PHASE_ATTRIBUTES_BEFORE + (
    b'/agent_tools/tests/fixtures/windows_host_phase_integration/** -text\n'
    b'/agent_tools/tests/fixtures/windows_host_work/** -text\n'
)
PUBLIC_FRAME_BYTE_FIXTURES = (
    ('agent_tools/tests/fixtures/tart_public_recipient_guard/public-crops.png',
     'fb0e2f150b5797a4306685192f327765bdb7cc74bcb6a285d94a09268bca9eb6', None),
    ('agent_tools/tests/fixtures/tart_public_recipient_guard/public-header-mask.json',
     'f8c2130bd1266c3d517b7981f02b7c71274b4fb15f5f6fa9b839f51b89e1db18', None),
    ('agent_tools/tests/fixtures/windows_login_caret_profile/native-empty-field.ppm.zlib',
     '345149552391afa5243dae9cf70aad69f7e32b5b37a2968f729476625bb6a0ca', None),
    ('agent_tools/tests/fixtures/windows_login_selected_tile/native-refused-field.ppm.zlib',
     'df5de4d0947e4925396651daec6f064477d1a1916879e04f85ec5e9ff380b420', None),
    ('agent_tools/tests/fixtures/windows_login_spotlight_profile/native-before-return.ppm.zlib',
     'e130eb383f96674a3292c64ce81b792bec2e103e2dcc0b08b128529b3cc6ae4b', None),
)

# Complete policy before protecting these four reader-authenticated failures.
SOURCE_DEPENDENCY_ATTRIBUTES_BEFORE = PUBLIC_FRAME_ATTRIBUTES_BEFORE + (
    b'/agent_tools/tests/fixtures/tart_public_recipient_guard/public-crops.png -text\n'
    b'/agent_tools/tests/fixtures/tart_public_recipient_guard/public-header-mask.json -text\n'
    b'/agent_tools/tests/fixtures/windows_login_caret_profile/native-empty-field.ppm.zlib -text\n'
    b'/agent_tools/tests/fixtures/windows_login_selected_tile/native-refused-field.ppm.zlib -text\n'
    b'/agent_tools/tests/fixtures/windows_login_spotlight_profile/native-before-return.ppm.zlib -text\n'
)
SOURCE_DEPENDENCY_BYTE_FIXTURES = (
    ('agent_tools/tests/fixtures/native_context_dynamic_catalogue/actual-failure.txt',
     '3292e9fb4cce003f1a5ca797ef651707b23c668b76ed6b4d03819392ad63c9ae', None),
    ('agent_tools/tests/fixtures/ssh_close_import_dependency/actual-failure.txt',
     'e6a3e461d84d2d9d5f70230d8da2b1b423a1953f6c70cd8f2eb5cf36dd02a3a8', None),
    ('agent_tools/tests/fixtures/native_engineering_transport_seam/actual-failure.txt',
     'c318a1ce31eca12ff0967aa8ef3915e6458e50860ff4656a7210d186904094ad', None),
    ('agent_tools/tests/fixtures/native_context_helper_fixture/actual-failure.txt',
     '463bf3bee49d15c446e822cee64477bb0c262be710128500bffa017c8b622adb', None),
)

LEASE_POLICY_ATTRIBUTES_BEFORE = SOURCE_DEPENDENCY_ATTRIBUTES_BEFORE + (
    b'/agent_tools/tests/fixtures/native_context_dynamic_catalogue/actual-failure.txt -text\n'
    b'/agent_tools/tests/fixtures/ssh_close_import_dependency/actual-failure.txt -text\n'
    b'/agent_tools/tests/fixtures/native_engineering_transport_seam/actual-failure.txt -text\n'
    b'/agent_tools/tests/fixtures/native_context_helper_fixture/actual-failure.txt -text\n'
)
LEASE_POLICY_BYTE_FIXTURES = (
    ('agent_tools/tests/fixtures/lease_provider_policy/actual-mismatch.json',
     'bdd8613991a67bb27a0db50bb8d633fc7c14a2d4a33da4ec8dc9133fb6b60b81', None),
    ('agent_tools/tests/fixtures/lease_provider_policy/policy.before.json',
     '1973cf412c9221379c1f4c78d6fe94f931eca1f6aa3167a827ac07c6e25df1db', None),
    ('agent_tools/tests/fixtures/lease_provider_policy_runtime/actual-mismatch.json',
     '3f03b86a3367381c0cb40209f4889bc338c89a3fb63303458179599d203abd07', None),
    ('agent_tools/tests/fixtures/vm_dispatch_context_test_seam/actual-failure.txt',
     'c98c0f967e96d5bb2c32cbcf06ed6d6398388a46b8c9ad1956d309432a22ba25', None),
)

# Full preceding byte-policy epoch; every selected payload actually changed
# in the controlled Git core.autocrlf checkout before its exact-path enrollment.
AUDITED_RAW_ATTRIBUTES_BEFORE = LEASE_POLICY_ATTRIBUTES_BEFORE + (
    b'/agent_tools/tests/fixtures/lease_provider_policy/actual-mismatch.json -text\n'
    b'/agent_tools/tests/fixtures/lease_provider_policy/policy.before.json -text\n'
    b'/agent_tools/tests/fixtures/lease_provider_policy_runtime/actual-mismatch.json -text\n'
    b'/agent_tools/tests/fixtures/vm_dispatch_context_test_seam/actual-failure.txt -text\n'
)
AUDITED_RAW_BYTE_FIXTURES = (
    ('agent_tools/tests/fixtures/agent_test_session_observer/actual-failure.json',
     'f307a1adad09c9e9dae41f534687e384c4e63d9d42f4f007eeb2a95aa39dcd59', None),
    ('agent_tools/tests/fixtures/confinement_attach_selector/attach-2gib.plist',
     'c4adea0c69e98f5219ea865693c2b8e4323c2e5c4f863ccc4f04a989bead6f99', None),
    ('agent_tools/tests/fixtures/confinement_attach_selector/attach-64mib.plist',
     'ef6b03599e14bd476c789d790010ba5e1d4cd099a6538afd5faa3ef2bff4f8ac', None),
    ('agent_tools/tests/fixtures/confinement_attach_selector/hdi-2gib-info.plist',
     '2c4d76e1670a540e5973c24b52ae8dfd5a06683397a964d53c0ead2baf01c1d7', None),
    ('agent_tools/tests/fixtures/native_mcp_environment_seam/actual-failure.txt',
     '5439f5736c125f8edb12cefe1fd3caf8767d96640b486ac171650c61532f643c', None),
    ('agent_tools/tests/fixtures/native_mcp_environment_seam/bypassed-admission-failure.txt',
     '4094032b14576574a0ad3f156bc84a73c0271b873a87ed175cb245fb7d4ddf98', None),
    ('agent_tools/tests/fixtures/ssh_acceptance_owner_readiness/original61bd.failure-provenance.json',
     '55cbe1d429b905075a4bd02faa0def597b5229975c52849bd5e545bb250bb3b7', None),
    ('agent_tools/tests/fixtures/ssh_acceptance_owner_readiness/original61bd.failure.txt',
     'c8d02aee88cd371583ead067cccc3e88467854005b27d2ceff4bd5ecbaad9d19', None),
    ('agent_tools/tests/fixtures/tart_macos_parent_caller/dependencies/plan.json',
     '1f8515a9e38aeb6f0dd30cbe58a5fa7161e8f3440f8346cc03504cc7cee52a43', None),
    ('agent_tools/tests/fixtures/windows_bootstrap_dispatch/provenance.json',
     'e61ffde1fab14a3dc4ca1188ce87ec24754f2b9f50cf304123a4c2171fb4e1c5', None),
    ('agent_tools/tests/fixtures/windows_bootstrap_durable/carrier-argv-native-failure.json',
     'bdb241c6169c3c9b127489c85a6f565cc6a43bf64ef5edd8367dfdc21c88ef26', None),
    ('agent_tools/tests/fixtures/windows_bootstrap_durable/carrier-failure.json',
     '0955149a517e0c6ad77a8677c99a15b97f314b00d8dce64bbc52c8fef3a57e0e', None),
    ('agent_tools/tests/fixtures/windows_bootstrap_durable/carrier.provenance.json',
     'e38b8211b0433ae80154aad1cae982bc8b29011bc1a1564e661f6900d30dc52f', None),
    ('agent_tools/tests/fixtures/windows_bootstrap_durable/provenance.json',
     '2dad915313444eb7aeab4cd899e6355eb515e01719e545a9bd1de72ad829c789', None),
    ('agent_tools/tests/fixtures/windows_bootstrap_integration/provenance.json',
     '8a9f3ffce16585e7cb55bf2c463e2db2259424bef6db3de3cb8de9dbc157cc17', None),
    ('agent_tools/tests/fixtures/windows_credential_explicit_target/probe-test-failure.json',
     '50de4eb8be6b158dbdb0a6a761febad611a48aea0a48772c4e56ce823082c009', None),
    ('agent_tools/tests/fixtures/windows_managed_admission/graph-local-failure.json',
     'd32d67fbd0e3d3adf54acd04d0b165201dd34880559cee959e4aea6dfb2e156e', None),
    ('agent_tools/tests/fixtures/windows_managed_admission/provenance.json',
     '9b6232c1974e984839c8d3f6dfdd654e3328f1dc2559407c9553473ad14bc5bf', None),
    ('agent_tools/tests/fixtures/windows_managed_admission/runtime-id-final-type.provenance.json',
     'caa3a07dc231d1fbcd0511fc032951b38d795a1aa9a627d020d541d19fa151df', None),
    ('agent_tools/tests/fixtures/windows_managed_admission/runtime-id.provenance.json',
     'cba22fe6b5eaa4a46671d43369625c4c536588e7de34865d4fa0d50265f03405', None),
)
# Complete policy before the four newly frozen RAW-SHA receipts were enrolled.
# Reconstruct every preceding line, including the prior exact twenty-path epoch.
ARCHIVE_NESTED_ATTRIBUTES_BEFORE = AUDITED_RAW_ATTRIBUTES_BEFORE + (
    b'\n# These additional reviewed fixture readers authenticate raw payload bytes.\n' +
    b''.join(('/' + name + ' -text\n').encode() for name, _, _ in AUDITED_RAW_BYTE_FIXTURES)
)
ARCHIVE_NESTED_BYTE_FIXTURES = (
    ('agent_tools/tests/fixtures/archive_directory_identity/native-failure.json',
     '5c1ed3c543ab7df0afc0a9cc5aeaf779df933037a3aea16423e8fe1ff1b24e41', None),
    ('agent_tools/tests/fixtures/windows_bootstrap_nested_closure/native-failure.json',
     '11fa1b456f750c57b28d0ab705cc97574d8d42f3f7ebfc202d3dcef8f2b14ebb', None),
    ('agent_tools/tests/fixtures/windows_bootstrap_nested_closure/provenance.json',
     'de76947d3db3fc2666cfdacb7e958813865fba903a83c1a1116bb5f97be1108f', None),
    ('agent_tools/tests/fixtures/windows_bootstrap_nested_closure/run-owned-input-failure.json',
     '5640e3153902a0dee6bee7faf7ff34b4e1eb14398b3673caa32d5ebba4f35af7', None),
)
VISUAL_AVAILABILITY_BYTE_FIXTURES = (
    ('scripts/tests/fixtures/visual_availability_qualification/visual_platform.before.source',
     '1dcdc7cc160bcdd6ce6298ccca42f74318ea468705e9b27e197139eb919a0e00', None),
)
# Exact whole byte-policy epoch retained before the two PowerShell inputs.
# The suffix is copied from the closed original e0d9454b policy, not obtained by
# deleting current rules or refreshing any historical fixture digest.
WINDOWS_ACL_CREATION_ATTRIBUTES_BEFORE = ARCHIVE_NESTED_ATTRIBUTES_BEFORE + (
    b'\n'
    b'# Newly frozen archive and bootstrap receipts have exact raw SHA consumers.\n'
    b'/agent_tools/tests/fixtures/archive_directory_identity/native-failure.json -text\n'
    b'/agent_tools/tests/fixtures/windows_bootstrap_nested_closure/native-failure.json -text\n'
    b'/agent_tools/tests/fixtures/windows_bootstrap_nested_closure/provenance.json -text\n'
    b'/agent_tools/tests/fixtures/windows_bootstrap_nested_closure/run-owned-input-failure.json -text\n'
    b'\n'
    b'# The capability regression executes this whole source at its exact raw SHA.\n'
    b'/scripts/tests/fixtures/visual_availability_qualification/visual_platform.before.source -text\n'
    b'\n'
    b'# Exact raw-SHA inputs for the finite recovery caller regressions.\n'
    b'/agent_tools/tests/fixtures/ssh_acceptance_preparation/audit_prepared_sources.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_acceptance_preparation/build_controller_program_v2.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_acceptance_preparation/controller.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_acceptance_preparation/local-owner-source/local_owner.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_acceptance_preparation/local-owner-source/local_owner_v2.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_acceptance_preparation/local-owner-source/test_local_owner_v2.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_acceptance_preparation/ordinary_retention.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_acceptance_preparation/prepare_absolute_epoch.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_acceptance_preparation/prepare_sources.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_acceptance_preparation/provenance.json -text\n'
    b'/agent_tools/tests/fixtures/ssh_acceptance_preparation/relocated-wrapper-key.failure.txt -text\n'
    b'/agent_tools/tests/fixtures/ssh_acceptance_preparation/test_controller.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_acceptance_preparation/test_generic_bootstrap_program_path.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_acceptance_preparation/test_preparation_causals.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_acceptance_preparation/test_prepare_private_roots.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_acceptance_preparation/test_program_builder_v2.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_local_controller_owner/local-owner-source/local_owner.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_local_controller_owner/local-owner-source/local_owner_v2.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_local_controller_owner/local-owner-source/test_local_owner_v2.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_local_controller_owner/ordinary_retention.py -text\n'
    b'/agent_tools/tests/fixtures/ssh_local_controller_owner/provenance.json -text\n'
    b'/agent_tools/tests/fixtures/tart_macos_acl_diagnostic/fake_metadata.c -text\n'
    b'/agent_tools/tests/fixtures/tart_macos_acl_diagnostic/native-cap-failure.txt -text\n'
    b'/agent_tools/tests/fixtures/tart_macos_acl_diagnostic/native-result.json -text\n'
    b'/agent_tools/tests/fixtures/tart_macos_acl_diagnostic/native-rpc-closure.json -text\n'
    b'/agent_tools/tests/fixtures/tart_macos_acl_diagnostic/native-source-closing.json -text\n'
    b'/agent_tools/tests/fixtures/tart_macos_acl_diagnostic/provenance.json -text\n'
)
WINDOWS_ACL_CREATION_BYTE_FIXTURES = (
    ('agent_tools/tests/fixtures/windows_compile_acl_creation/parent-665b.before.ps1',
     '665b3d850627c5c01c669a5c9245f1df2a81d838ba7b28a940bdccdce483dd81', 10897),
    ('agent_tools/tests/fixtures/windows_compile_acl_creation/create-c9dad.fixed.ps1',
     'c9dad79f0f3abbeebb3cf7e02b36cf93ed2a5aed78b60aedad5c7a862cf1c026', 1514),
)
# Complete actual policy before the three proxy JSON raw-byte rules.
SSH_PROXY_DESCRIPTOR_ATTRIBUTES_BEFORE = WINDOWS_ACL_CREATION_ATTRIBUTES_BEFORE + (
    b'\n'
    b'# Exact PowerShell bytes for the native ACL constructor regression.\n'
    b'/agent_tools/tests/fixtures/windows_compile_acl_creation/parent-665b.before.ps1 -text\n'
    b'/agent_tools/tests/fixtures/windows_compile_acl_creation/create-c9dad.fixed.ps1 -text\n'
)
SSH_PROXY_DESCRIPTOR_BYTE_FIXTURES = (
    ('agent_tools/tests/fixtures/ssh_proxy_high_descriptors/provenance.json',
     '872453c7b71bb95b39732fb97430ceff3160f243d1cf7a0ae27dd9c37c2a96f9', None),
    ('agent_tools/tests/fixtures/ssh_proxy_high_descriptors/native-select-phase.json',
     '791c85947eec3550fc3651989f93287cf765c70b453d59349962dfce9544e8b2', None),
    ('agent_tools/tests/fixtures/ssh_proxy_high_descriptors/controlled-high-fd.actual.json',
     'f8938698fa4e93d5d1b3a5af152f89a33b73b3120f2e03fb9ffc26b9640daefd', None),
)
PARSE_ONLY_MANIFESTS = (
    'agent_tools/tests/fixtures/archive_directory_identity/provenance.json',
    'agent_tools/tests/fixtures/confinement_attach_selector/provenance.json',
    'agent_tools/tests/fixtures/tart_macos_parent_caller/provenance.json',
    'agent_tools/tests/fixtures/ssh_acceptance_owner_readiness/provenance.json',
)

class HistoricalFixtureCheckoutBytesTest(unittest.TestCase):
    def _verify_checkout(self, attributes, corrupted=(), extra_files=(), required_unset=(), required_unspecified=()):
        fixtures = [(name, expected, None) for name, expected in FIXTURES]
        for family in PINNED_FAMILIES:
            pins = json.loads((ROOT / family / "fixture-pins.json").read_bytes())["files"]
            fixtures.extend((f"{family}/{name}", pin["sha256"], pin["bytes"])
                            for name, pin in pins.items())
        for family, manifest, sections in RAW_PROVENANCE_FAMILIES:
            provenance = json.loads((ROOT / family / manifest).read_bytes())
            for section in sections:
                fixtures.extend((f"{family}/{name}", digest, None)
                                for name, digest in provenance[section].items())
        fixtures.extend(extra_files)
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        with tempfile.TemporaryDirectory(prefix="fixture-checkout-") as directory:
            checkout = Path(directory)

            def git(*args):
                result = subprocess.run(
                    ["git", "-c", "core.autocrlf=true", "-c", "core.safecrlf=false", *args],
                    cwd=checkout, env=env, capture_output=True, timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                return result.stdout

            git("init", "--quiet")
            (checkout / ".gitattributes").write_bytes(attributes)
            for name, expected, expected_bytes in fixtures:
                raw = (ROOT / name).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
                if expected_bytes is not None:
                    self.assertEqual(len(raw), expected_bytes)
                target = checkout / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            control = "checkout-conversion-control.txt"
            (checkout / control).write_bytes(b"unprotected LF text\nsecond line\n")
            git("add", "--", ".gitattributes", control,
                *(name for name, _, _ in fixtures))
            for name, _, _ in fixtures:
                (checkout / name).unlink()
            (checkout / control).unlink()
            git("checkout-index", "--all")
            if required_unset:
                actual = git("check-attr", "-z", "text", "--", *sorted(required_unset)).decode().split("\0")
                self.assertEqual({name: ("text", "unset") for name in required_unset},
                                 {actual[index]: tuple(actual[index + 1:index + 3])
                                  for index in range(0, len(actual) - 1, 3)})
            if required_unspecified:
                actual = git("check-attr", "-z", "text", "--", *sorted(required_unspecified)).decode().split("\0")
                self.assertEqual({name: ("text", "unspecified") for name in required_unspecified},
                                 {actual[index]: tuple(actual[index + 1:index + 3])
                                  for index in range(0, len(actual) - 1, 3)})
            self.assertEqual((checkout / control).read_bytes(),
                             b"unprotected LF text\r\nsecond line\r\n")
            for name, expected, expected_bytes in fixtures:
                with self.subTest(fixture=name):
                    raw = (checkout / name).read_bytes()
                    if name in corrupted:
                        self.assertNotEqual(hashlib.sha256(raw).hexdigest(), expected)
                    else:
                        self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
                    if expected_bytes is not None and name not in corrupted:
                        self.assertEqual(len(raw), expected_bytes)

    def test_windows_checkout_preserves_exact_historical_bytes(self):
        self._verify_checkout((ROOT / ".gitattributes").read_bytes(), extra_files=(self.extended_files() + list(DEPENDENCY_BYTE_FIXTURES) +
                                                                         list(ENROLLMENT_BYTE_FIXTURES) + list(CLOSED_FAMILY_BYTE_FIXTURES) +
                                                                         list(SCRIPT_SEAM_BYTE_FIXTURES) + list(HOST_PHASE_BYTE_FIXTURES) +
                                                                         list(PUBLIC_FRAME_BYTE_FIXTURES) + list(SOURCE_DEPENDENCY_BYTE_FIXTURES) +
                                                                         list(LEASE_POLICY_BYTE_FIXTURES) + list(AUDITED_RAW_BYTE_FIXTURES) +
                                                                         list(ARCHIVE_NESTED_BYTE_FIXTURES) + list(VISUAL_AVAILABILITY_BYTE_FIXTURES) +
                                                                         list(WINDOWS_ACL_CREATION_BYTE_FIXTURES) + list(SSH_PROXY_DESCRIPTOR_BYTE_FIXTURES)),
                              required_unset={name for name, _, _ in
                                              PUBLIC_FRAME_BYTE_FIXTURES + SOURCE_DEPENDENCY_BYTE_FIXTURES + LEASE_POLICY_BYTE_FIXTURES + AUDITED_RAW_BYTE_FIXTURES + ARCHIVE_NESTED_BYTE_FIXTURES + VISUAL_AVAILABILITY_BYTE_FIXTURES + WINDOWS_ACL_CREATION_BYTE_FIXTURES + SSH_PROXY_DESCRIPTOR_BYTE_FIXTURES},
                              required_unspecified=PARSE_ONLY_MANIFESTS)

    def extended_files(self):
        result = []
        for family in ('windows_jobs_default_owner', 'windows_desktop_background_roles', 'windows_jobs_preexec'):
            prefix = 'agent_tools/tests/fixtures/' + family
            pins = json.loads((ROOT / prefix / 'provenance.json').read_bytes())['sourceSha256']
            result.extend((prefix + '/' + name, digest, None) for name, digest in pins.items())
        prefix = 'agent_tools/tests/fixtures/resource_running_actor_before'
        pins = json.loads((ROOT / prefix / 'provenance.json').read_bytes())
        result.append((prefix + '/public-measurement.json', pins['publicMeasurementSha256'], None))
        prefix = 'agent_tools/tests/fixtures/windows_defender_installed_service'
        pins = json.loads((ROOT / prefix / 'provenance.json').read_bytes())['files']
        result.extend((prefix + '/' + name, pin['sha256'], pin['bytes']) for name, pin in pins.items())
        prefix = 'agent_tools/tests/fixtures/tart_virtiofs_python_copy'
        pins = json.loads((ROOT / prefix / 'provenance.json').read_bytes())
        result.extend((prefix + '/' + name, digest, None) for name, digest in pins['sourceSha256'].items())
        result.append((prefix + '/native-public-evidence.json', pins['nativePublicEvidenceSha256'], None))
        prefix = 'scripts/tests/fixtures/visual_target_before'
        pins = json.loads((ROOT / prefix / 'provenance.json').read_bytes())
        result.extend((entry['fixture'], entry['sha256'], None) for entry in pins.values())
        return result

    def test_actual_old_attributes_corrupt_new_provider_evidence(self):
        family = ROOT / 'agent_tools/tests/fixtures/recovery_checkout_extended'
        attributes = (family / 'attributes.before').read_bytes()
        pin = json.loads((family / 'provenance.json').read_bytes())['sha256']
        self.assertEqual(hashlib.sha256(attributes).hexdigest(), pin)
        extra = self.extended_files()
        corrupted = {name for name, _, _ in extra
                     if name.endswith(('.json', '.sh')) or name.startswith('scripts/')}
        self.assertEqual(len(corrupted), 16)
        self._verify_checkout(attributes, corrupted=corrupted, extra_files=extra)

    def test_complete_pre_enrollment_attributes_corrupt_exact_dependency_evidence(self):
        self.assertEqual(hashlib.sha256(DEPENDENCY_ATTRIBUTES_BEFORE).hexdigest(),
                         "1928b94181a87364ffe1fdefe6435d60082587e24ed6d988f6ef45b581964789")
        corrupted = {name for name, _, _ in DEPENDENCY_BYTE_FIXTURES}
        self.assertEqual(10, len(corrupted))
        self._verify_checkout(DEPENDENCY_ATTRIBUTES_BEFORE, corrupted=corrupted,
                              extra_files=DEPENDENCY_BYTE_FIXTURES)

    def test_complete_before_enrollment_corrupts_native_provenance_receipts(self):
        self.assertEqual("bb9570ad39b7f502405a66b991cf2a5cc169ccc0dc6523cf692e6f7529b69954",
                         hashlib.sha256(ENROLLMENT_ATTRIBUTES_BEFORE).hexdigest())
        corrupted = {name for name, _, _ in ENROLLMENT_BYTE_FIXTURES}
        self.assertEqual(2, len(corrupted))
        self._verify_checkout(ENROLLMENT_ATTRIBUTES_BEFORE, corrupted=corrupted,
                              extra_files=ENROLLMENT_BYTE_FIXTURES)

    def test_complete_before_closed_family_provenance_and_failure_bytes_corrupt(self):
        self.assertEqual("59a8918b79c391b10fa97dc356d44f2799934da67387841bb619d99927de6187",
                         hashlib.sha256(CLOSED_FAMILY_ATTRIBUTES_BEFORE).hexdigest())
        corrupted = {name for name, _, _ in CLOSED_FAMILY_BYTE_FIXTURES}
        self.assertEqual(6, len(corrupted))
        self._verify_checkout(CLOSED_FAMILY_ATTRIBUTES_BEFORE, corrupted=corrupted,
                              extra_files=CLOSED_FAMILY_BYTE_FIXTURES)

    def test_complete_before_script_sources_and_receipts_corrupt(self):
        self.assertEqual("a51ae469fbeeb53dff35310e5439e1b3f3da48992fba568e97514ae39a3291ee",
                         hashlib.sha256(SCRIPT_SEAM_ATTRIBUTES_BEFORE).hexdigest())
        corrupted = {name for name, _, _ in SCRIPT_SEAM_BYTE_FIXTURES}
        self.assertEqual(4, len(corrupted))
        self._verify_checkout(SCRIPT_SEAM_ATTRIBUTES_BEFORE, corrupted=corrupted,
                              extra_files=SCRIPT_SEAM_BYTE_FIXTURES)

    def test_complete_before_original_windows_host_phase_receipts_corrupt(self):
        self.assertEqual("f548ee4437c0ad7741a8409e875248c04baf9b407d6025e75f22d27b2fdb26eb",
                         hashlib.sha256(HOST_PHASE_ATTRIBUTES_BEFORE).hexdigest())
        corrupted = {name for name, _, _ in HOST_PHASE_BYTE_FIXTURES}
        self.assertEqual(11, len(corrupted))
        self._verify_checkout(HOST_PHASE_ATTRIBUTES_BEFORE, corrupted=corrupted,
                              extra_files=HOST_PHASE_BYTE_FIXTURES)

    def test_complete_before_public_mask_corrupts_while_binary_frames_stay_intact(self):
        self.assertEqual("b3a83636acfc6c51bbc9bb52ac8cf9a8e6b22bcf70bf02c9ae92cdf2aff7a972",
                         hashlib.sha256(PUBLIC_FRAME_ATTRIBUTES_BEFORE).hexdigest())
        self.assertEqual(5, len(PUBLIC_FRAME_BYTE_FIXTURES))
        # Actual Git binary heuristics already preserve the PNG and zlib files.
        # Only the JSON mask is a causal CRLF failure; no binary RED is claimed.
        corrupted = {"agent_tools/tests/fixtures/tart_public_recipient_guard/public-header-mask.json"}
        self._verify_checkout(PUBLIC_FRAME_ATTRIBUTES_BEFORE, corrupted=corrupted,
                              extra_files=PUBLIC_FRAME_BYTE_FIXTURES)

    def test_complete_before_source_dependency_failure_bytes_corrupt(self):
        self.assertEqual("9b7b787cf7adb684ba0e2b19a7d52c3fde080859e4269e6baec1374daefb5b50",
                         hashlib.sha256(SOURCE_DEPENDENCY_ATTRIBUTES_BEFORE).hexdigest())
        corrupted = {name for name, _, _ in SOURCE_DEPENDENCY_BYTE_FIXTURES}
        self.assertEqual(4, len(corrupted))
        self._verify_checkout(SOURCE_DEPENDENCY_ATTRIBUTES_BEFORE, corrupted=corrupted,
                              extra_files=SOURCE_DEPENDENCY_BYTE_FIXTURES)

    def test_complete_before_lease_policy_and_dispatch_evidence_corrupt(self):
        self.assertEqual('1ce634ad5b9291c4c66eeda2dcf201097ac977f4abfa4314dd993de263512375',
                         hashlib.sha256(LEASE_POLICY_ATTRIBUTES_BEFORE).hexdigest())
        corrupted = {name for name, _, _ in LEASE_POLICY_BYTE_FIXTURES}
        self.assertEqual(4, len(corrupted))
        self._verify_checkout(LEASE_POLICY_ATTRIBUTES_BEFORE, corrupted=corrupted,
                              extra_files=LEASE_POLICY_BYTE_FIXTURES)

    def test_actual_old_attributes_corrupt_reflection_native_evidence(self):
        family = ROOT / "agent_tools/tests/fixtures/recovery_fixture_checkout_bytes"
        attributes = (family / "attributes.before").read_bytes()
        expected = json.loads((family / "provenance.json").read_bytes())["sha256"]
        self.assertEqual(hashlib.sha256(attributes).hexdigest(), expected)
        self._verify_checkout(attributes, corrupted={
            "agent_tools/tests/fixtures/windows_jobs_reflection/" + name
            for name in ("reflection.causal.ps1", "native-failure.json",
                         "native-conversion-failure.json", "native-green.json")
        })

    def test_complete_before_audited_raw_fixture_readers_corrupt_exact_payloads(self):
        self.assertEqual('04f21d11f8cee5116c809b6c94b15616cb4f9711e395753d62df48eacdcc8c99',
                         hashlib.sha256(AUDITED_RAW_ATTRIBUTES_BEFORE).hexdigest())
        corrupted = {name for name, _, _ in AUDITED_RAW_BYTE_FIXTURES}
        self.assertEqual(20, len(corrupted))
        self._verify_checkout(AUDITED_RAW_ATTRIBUTES_BEFORE, corrupted=corrupted,
                              extra_files=AUDITED_RAW_BYTE_FIXTURES,
                              required_unspecified=PARSE_ONLY_MANIFESTS)

    def test_complete_before_archive_and_nested_bootstrap_raw_receipts_corrupt(self):
        self.assertEqual('bd4f742f63cdfb213cfaa4149b752ac890e3d2c1c994072745bc76e4c1452d89',
                         hashlib.sha256(ARCHIVE_NESTED_ATTRIBUTES_BEFORE).hexdigest())
        corrupted = {name for name, _, _ in ARCHIVE_NESTED_BYTE_FIXTURES}
        self.assertEqual(4, len(corrupted))
        self._verify_checkout(ARCHIVE_NESTED_ATTRIBUTES_BEFORE, corrupted=corrupted,
                              extra_files=ARCHIVE_NESTED_BYTE_FIXTURES,
                              required_unspecified=PARSE_ONLY_MANIFESTS)

    def test_actual_old_attributes_corrupt_visual_availability_beforeimage(self):
        # Reuse the complete authenticated historical policy; do not remove a
        # current rule or disable conversion globally to manufacture the RED.
        self.assertEqual('bd4f742f63cdfb213cfaa4149b752ac890e3d2c1c994072745bc76e4c1452d89',
                         hashlib.sha256(ARCHIVE_NESTED_ATTRIBUTES_BEFORE).hexdigest())
        corrupted = {name for name, _, _ in VISUAL_AVAILABILITY_BYTE_FIXTURES}
        self.assertEqual(1, len(corrupted))
        self._verify_checkout(ARCHIVE_NESTED_ATTRIBUTES_BEFORE, corrupted=corrupted,
                              extra_files=VISUAL_AVAILABILITY_BYTE_FIXTURES,
                              required_unspecified=corrupted)

    def test_complete_before_windows_acl_creation_sources_corrupt(self):
        self.assertEqual('e0d9454b2743d1bc4643f0864e5f1574a8d37d1f8c162f3943dbfd8a6ebcb14d',
                         hashlib.sha256(WINDOWS_ACL_CREATION_ATTRIBUTES_BEFORE).hexdigest())
        corrupted = {name for name, _, _ in WINDOWS_ACL_CREATION_BYTE_FIXTURES}
        self.assertEqual(2, len(corrupted))
        self._verify_checkout(WINDOWS_ACL_CREATION_ATTRIBUTES_BEFORE, corrupted=corrupted,
                              extra_files=WINDOWS_ACL_CREATION_BYTE_FIXTURES,
                              required_unspecified=corrupted)

    def test_complete_before_proxy_descriptor_json_bytes_corrupt(self):
        self.assertEqual('6a1490dead401d831ad0feb50562c7fc53534eda3a129466b3ead9327d0bec5f',
                         hashlib.sha256(SSH_PROXY_DESCRIPTOR_ATTRIBUTES_BEFORE).hexdigest())
        corrupted = {name for name, _, _ in SSH_PROXY_DESCRIPTOR_BYTE_FIXTURES}
        self.assertEqual(3, len(corrupted))
        self._verify_checkout(SSH_PROXY_DESCRIPTOR_ATTRIBUTES_BEFORE, corrupted=corrupted,
                              extra_files=SSH_PROXY_DESCRIPTOR_BYTE_FIXTURES,
                              required_unspecified=corrupted)
