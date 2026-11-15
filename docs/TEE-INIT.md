# TEE initialization ownership

`hardware/huawei` separates the legacy `/data/sec_storage_data*` core-data
labels from the secure-storage filesystem and writable vendor data. Android17
`vendor_init` excludes `core_data_file_type` from directory creation/relabeling.
Keep these two legacy mkdir/restorecon pairs under core init by installing
`init.tee.core.rc` into `/system_ext/etc/init/`, which init auto-imports. Vendor
and ODM paths alone use the vendor subcontext (`system/core/init/subcontext.cpp`).
The vendor-installed `init.tee.rc` retains vendor data setup and TEE services.

Only those four commands move. Modes (0700), system ownership, trigger and the
inherited `encryption=None` mkdir arguments remain unchanged; this source change
does not disable userdata encryption or establish FBE/TEE functionality. It
adds no cross-domain access exceptions. TEE service domain/permission integration
and encryption compatibility remain separate work.

Host regressions verify the image destination, exclusive action ownership,
private directory modes and retained vendor setup. The actual build must also
install both rc files and validate syntax with the selected `host_init_verifier`.
No phone operation is part of these checks.
