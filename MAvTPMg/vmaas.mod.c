#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xf704969, "module_layout" },
	{ 0xdb0f1622, "seq_release" },
	{ 0xbe503d2d, "seq_read" },
	{ 0x3d9d351b, "seq_lseek" },
	{ 0xdce9f68d, "param_ops_charp" },
	{ 0xc0421c5e, "tracepoint_probe_unregister" },
	{ 0xf188a662, "rhashtable_walk_exit" },
	{ 0x9cd7551a, "rhashtable_walk_stop" },
	{ 0xac505f6, "netlink_kernel_release" },
	{ 0x24b98ec5, "tpm_default_chip" },
	{ 0xef0f9ec2, "crypto_alloc_shash" },
	{ 0x9ba86cf2, "tracepoint_probe_register" },
	{ 0x16e84160, "for_each_kernel_tracepoint" },
	{ 0x1919e49e, "__netlink_kernel_create" },
	{ 0xa21071e2, "init_net" },
	{ 0xc04035ca, "securityfs_create_dir" },
	{ 0x4b5acf74, "rhashtable_init" },
	{ 0xcd24e146, "hash_digest_size" },
	{ 0x81188c30, "match_string" },
	{ 0xc3c4c6cc, "hash_algo_name" },
	{ 0x821f362f, "netlink_unicast" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x27a7893a, "securityfs_remove" },
	{ 0x8c8569cb, "kstrtoint" },
	{ 0x85df9b6c, "strsep" },
	{ 0xfeca427b, "securityfs_create_file" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0xf0c7d3c7, "crypto_shash_final" },
	{ 0x9b9d439f, "crypto_shash_update" },
	{ 0x8522d6bc, "strncpy_from_user" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0xe0313d71, "rhashtable_insert_slow" },
	{ 0xb202f0d7, "rht_bucket_nested_insert" },
	{ 0x37a0cba, "kfree" },
	{ 0x656e4a6e, "snprintf" },
	{ 0x7c797b6, "kmem_cache_alloc_trace" },
	{ 0xd731cdd9, "kmalloc_caches" },
	{ 0x18554f24, "current_task" },
	{ 0xfb578fc5, "memset" },
	{ 0x54b1fac6, "__ubsan_handle_load_invalid_value" },
	{ 0xc5b6f236, "queue_work_on" },
	{ 0x2d3385d3, "system_wq" },
	{ 0xd0d156e9, "__rht_bucket_nested" },
	{ 0x3c3fce39, "__local_bh_enable_ip" },
	{ 0x4629334c, "__preempt_count" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0xb7f990e9, "rht_bucket_nested" },
	{ 0x449ad0a7, "memcmp" },
	{ 0x76a4937f, "netlink_broadcast" },
	{ 0xe914e41e, "strcpy" },
	{ 0x72c9f28b, "__nlmsg_put" },
	{ 0xd8a85e15, "__alloc_skb" },
	{ 0x754d539c, "strlen" },
	{ 0x4555b13b, "tpm_pcr_extend" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x69acdf38, "memcpy" },
	{ 0xc1241fd1, "tpm_pcr_read" },
	{ 0x27d06596, "seq_open" },
	{ 0x826708e4, "seq_puts" },
	{ 0x2d5f69b3, "rcu_read_unlock_strict" },
	{ 0x54651f9b, "rhashtable_walk_next" },
	{ 0x9a5dce5c, "rhashtable_walk_start_check" },
	{ 0xe5ce1a56, "rhashtable_walk_enter" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0xd78b86c9, "seq_printf" },
	{ 0x92997ed8, "_printk" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "4C2795FA389A95122D6BC37");
