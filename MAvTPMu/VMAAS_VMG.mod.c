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
	{ 0x52fe1c20, "module_layout" },
	{ 0x929b4c44, "seq_release" },
	{ 0xde4a9d4, "seq_read" },
	{ 0xf8dbac4b, "seq_lseek" },
	{ 0xb85d9be7, "param_ops_charp" },
	{ 0x75b39b82, "netlink_kernel_release" },
	{ 0x7aa2e919, "tpm_default_chip" },
	{ 0x8ce4c068, "crypto_alloc_shash" },
	{ 0xad5c0f4a, "__netlink_kernel_create" },
	{ 0x5d882836, "init_net" },
	{ 0xfc5e3048, "securityfs_create_dir" },
	{ 0x4b5acf74, "rhashtable_init" },
	{ 0xcd24e146, "hash_digest_size" },
	{ 0x81188c30, "match_string" },
	{ 0xc3c4c6cc, "hash_algo_name" },
	{ 0x18ff417b, "netlink_unicast" },
	{ 0xfc6a17da, "__nlmsg_put" },
	{ 0xcead7af3, "__alloc_skb" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x656e4a6e, "snprintf" },
	{ 0xb3be5c80, "securityfs_remove" },
	{ 0x8c8569cb, "kstrtoint" },
	{ 0x85df9b6c, "strsep" },
	{ 0x198415c6, "securityfs_create_file" },
	{ 0xe914e41e, "strcpy" },
	{ 0xdd41dcc4, "kmem_cache_alloc_trace" },
	{ 0xf2b1403, "kmalloc_caches" },
	{ 0x37a0cba, "kfree" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x754d539c, "strlen" },
	{ 0x54b1fac6, "__ubsan_handle_load_invalid_value" },
	{ 0xd0d156e9, "__rht_bucket_nested" },
	{ 0x66cca4f9, "__x86_indirect_thunk_rcx" },
	{ 0xe0313d71, "rhashtable_insert_slow" },
	{ 0xb202f0d7, "rht_bucket_nested_insert" },
	{ 0xc5b6f236, "queue_work_on" },
	{ 0x2d3385d3, "system_wq" },
	{ 0x3c3fce39, "__local_bh_enable_ip" },
	{ 0x4629334c, "__preempt_count" },
	{ 0xb7f990e9, "rht_bucket_nested" },
	{ 0x449ad0a7, "memcmp" },
	{ 0xf188a662, "rhashtable_walk_exit" },
	{ 0x9cd7551a, "rhashtable_walk_stop" },
	{ 0x92da40e0, "crypto_shash_final" },
	{ 0xef82fef9, "crypto_shash_update" },
	{ 0xfb578fc5, "memset" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0x8bb64bec, "tpm_pcr_extend" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0x92997ed8, "_printk" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x69acdf38, "memcpy" },
	{ 0x954b8cc5, "tpm_pcr_read" },
	{ 0x7017d86a, "seq_open" },
	{ 0x29363f1f, "seq_puts" },
	{ 0x2d5f69b3, "rcu_read_unlock_strict" },
	{ 0x54651f9b, "rhashtable_walk_next" },
	{ 0x9a5dce5c, "rhashtable_walk_start_check" },
	{ 0xe5ce1a56, "rhashtable_walk_enter" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0xd8912672, "seq_printf" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x5b8239ca, "__x86_return_thunk" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "33AA849853E0AC0DB0414FF");
