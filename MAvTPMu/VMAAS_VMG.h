#include <crypto/hash.h>
#include <linux/rhashtable.h>
#include <linux/tpm.h>
#include <net/sock.h>


#define NETLINK_USER 21


struct dentry *vmaas_dir;
struct dentry *vmaas_vmg_dir;

struct tpm_chip *tpm_chip_info;
int VPCR_DATA_SIZE = 20;

bool bind_vpcr = false;
struct tpm_digest last_vpcr_extend;
struct tpm_digest history_11;
struct tpm_digest history_15;

bool bind_permamall = false;
struct tpm_digest last_permamall_extend;
struct tpm_digest history_12;
struct tpm_digest history_16;

static char *ima_hash = "sha256";
static int ima_hash_algo = HASH_ALGO_SHA256;
static u16 tpm_hash_algo = TPM_ALG_SHA256;

static struct tpm_digest *digests_csma;
static int ima_init_digests(void);

struct ima_digest_data {
		u8 algo;
		u8 length;
		union {
				struct {
						u8 unused;
						u8 type;
				} sha256;
				struct {
						u8 type;
						u8 algo;
				} ng;
				u8 data[2];
		} xattr;

		u8 digest[0];
} __packed;

static struct crypto_shash *ima_shash_tfm;
unsigned int crypto_shash_descsize_length;
unsigned long ima_ahash_minsize = 1024;

static struct dentry *vpcr_file = NULL;
static struct dentry *permall_file = NULL;
static struct dentry *vpcr_vmg_file = NULL;
static struct dentry *permall_vmg_file = NULL;

struct vPCR_content {
	struct list_head list;
	unsigned char pcr[24][64];
};


struct rhashtable container_objects;
struct rhashtable vmg_objects;

struct VM_content {
	unsigned long key;
	struct rhash_head head;
	struct list_head list;
	struct dentry *container_file;
	char *VMID;
	unsigned char final_hash[64];
		unsigned char permanent_state_hash[64];
};


const static struct rhashtable_params object_params = {
	.key_len	 = sizeof(unsigned long),
	.key_offset	 = offsetof(struct VM_content, key),
	.head_offset = offsetof(struct VM_content, head),
};

unsigned long hash(const unsigned char *str);
static void *ima_ns_measurements_start(struct seq_file *m, loff_t *pos);
static void *ima_ns_measurements_next(struct seq_file *m, void *v, loff_t *pos);
static void ima_measurements_stop(struct seq_file *m, void *v);
int ima_ns_measurements_show(struct seq_file *m, void *v);

static const struct seq_operations ima_ns_measurements_seqops = {
	.start = ima_ns_measurements_start,
	.next = ima_ns_measurements_next,
	.stop = ima_measurements_stop,
	.show = ima_ns_measurements_show
};

static int ima_ns_measurements_open(struct inode *inode, struct file *file);

static const struct file_operations ima_ns_measurements_ops = {
	.open = ima_ns_measurements_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};



static void *ima_ns_measurements_vmg_start(struct seq_file *m, loff_t *pos);
static void *ima_ns_measurements_vmg_next(struct seq_file *m, void *v, loff_t *pos);
static void ima_measurements_vmg_stop(struct seq_file *m, void *v);
int ima_ns_measurements_vmg_show(struct seq_file *m, void *v);

static const struct seq_operations ima_ns_measurements_vmg_seqops = {
	.start = ima_ns_measurements_vmg_start,
	.next = ima_ns_measurements_vmg_next,
	.stop = ima_measurements_vmg_stop,
	.show = ima_ns_measurements_vmg_show
};

static int ima_ns_measurements_vmg_open(struct inode *inode, struct file *file);

static const struct file_operations ima_ns_measurements_vmg_ops = {
	.open = ima_ns_measurements_vmg_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};


/*
 * Starts a session and takes a position as an argument, returning an iterator which will start reading at that position
 * returns each element of the measurement list
 */
static void *vpcr_file_start(struct seq_file *m, loff_t *pos);
static void *vpcr_vmg_file_start(struct seq_file *m, loff_t *pos);

/*
 * Returns the next element (entry) of sequence
 */
static void *vpcr_file_next(struct seq_file *m, void *v, loff_t *pos);
static void *vpcr_vmg_file_next(struct seq_file *m, void *v, loff_t *pos);


/*
 * The vpcr_file_show() function should format the object currently pointed to by the iterator for output
 */
int vpcr_file_show(struct seq_file *m, void *v);
int vpcr_vmg_file_show(struct seq_file *m, void *v);


/*
 * The vpcr_file_stop  function closes a session; its job is to clean up
 */
static void vpcr_file_stop(struct seq_file *m, void *v);
static void vpcr_vmg_file_stop(struct seq_file *m, void *v);


static int vpcr_file_open(struct inode *inode, struct file *file);
static int vpcr_vmg_file_open(struct inode *inode, struct file *file);

static const struct seq_operations vpcr_file_seqops = {
		.start = vpcr_file_start,
		.next = vpcr_file_next,
		.stop = vpcr_file_stop,
		.show = vpcr_file_show
};

static const struct seq_operations vpcr_vmg_file_seqops = {
		.start = vpcr_vmg_file_start,
		.next = vpcr_vmg_file_next,
		.stop = vpcr_vmg_file_stop,
		.show = vpcr_vmg_file_show
};


/*
 * Structure that defines the functions that can be used with the vPCRs file.
 */
static const struct file_operations vpcr_file_ops = {
		.open = vpcr_file_open,
		.read = seq_read,
		.llseek = seq_lseek,
		.release = seq_release,
};

/*
 * Structure that defines the functions that can be used with the vPCRs file.
 */
static const struct file_operations vpcr_vmg_file_ops = {
		.open = vpcr_vmg_file_open,
		.read = seq_read,
		.llseek = seq_lseek,
		.release = seq_release,
};



int permall_file_show(struct seq_file *m, void *v);

static int permall_file_open(struct inode *inode, struct file *file);
static const struct seq_operations permall_file_seqops = {
		.start = vpcr_file_start,
		.next = vpcr_file_next,
		.stop = vpcr_file_stop,
		.show = permall_file_show
};

/*
 * Structure that defines the functions that can be used with the permalls file.
 */
static const struct file_operations permall_file_ops = {
		.open = permall_file_open,
		.read = seq_read,
		.llseek = seq_lseek,
		.release = seq_release,
};

struct rhashtable container_objects;

struct sock *nl_sk = NULL;

static void hello_nl_recv_msg(struct sk_buff *skb);
static int pcr_extend(struct tpm_digest *digests, u32 pcr);
static int pcr_read(u32 index, struct tpm_digest *digests);

int calc_vpcr_digest(struct VM_content *vm);
static int vpcr_bind(void);
static int vpcr_vmg_bind(void);
static int permall_bind(void);
static int permall_vmg_bind(void);

struct VM_content *get_init_vm(const unsigned char *VMID);
struct VM_content *get_init_vmg(const unsigned char *VMID);
int add_vm(char *result_received);
int add_vmg(char *result_received);
int del_vm(char *result_received);
int migrate_vm(char *result_received);
int add_permanent_state(char *result_received);
int add_snapshot(char *result_received);
