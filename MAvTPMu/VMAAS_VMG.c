#include "VMAAS_VMG.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("VMAAS");


#define IMA_MAX_DIGEST_SIZE	64
#define IMA_EVENT_NAME_LEN_MAX	255
#define IMA_DIGEST_SIZE		SHA1_DIGEST_SIZE


static void __init hash_setup(char *str){
	int j;
	int i = match_string(hash_algo_name, HASH_ALGO__LAST, str);

	struct tpm2_hash {
		unsigned int crypto_id;
		unsigned int tpm_id;
	};
	static struct tpm2_hash tpm2_hash_map[4] = {
		{HASH_ALGO_SHA1, TPM_ALG_SHA1},
		{HASH_ALGO_SHA256, TPM_ALG_SHA256},
		{HASH_ALGO_SHA384, TPM_ALG_SHA384},
		{HASH_ALGO_SHA512, TPM_ALG_SHA512},
	};
	for (j = 0; j < ARRAY_SIZE(tpm2_hash_map); j++) {
		if (i == tpm2_hash_map[j].crypto_id) {
			ima_hash_algo = i;
			tpm_hash_algo = tpm2_hash_map[j].tpm_id;
			break;
		}
	}
	VPCR_DATA_SIZE = hash_digest_size[ima_hash_algo];

}
module_param(ima_hash, charp, 0000);

/*
 * Function used to calculate key from container id
 */
unsigned long hash(const unsigned char *str) {
	unsigned long hash = 5381;
	int c;

	while ((c = *str++)){
		hash = ((hash << 5) + hash) + c;
	}
	return hash;
}

int calc_vpcr_digest(struct VM_content *vm) {

	int rc = 0;
	int i;
	struct tpm_digest digests;
	struct vPCR_content *vpcr_content;
	struct {
		struct shash_desc shash;
		char ctx[crypto_shash_descsize_length];
	} desc;

	desc.shash.tfm = ima_shash_tfm;

	memset(digests.digest, 0x00, VPCR_DATA_SIZE);

	rc = crypto_shash_init(&desc.shash);
	if (rc != 0){
		return rc;
	}
	vpcr_content = list_entry_rcu(vm->list.next, struct vPCR_content, list);
	for (i = 0; i < 24; i++) {
		crypto_shash_init(&desc.shash);
		crypto_shash_update(&desc.shash, digests.digest, VPCR_DATA_SIZE);

		crypto_shash_update(&desc.shash,vpcr_content->pcr[i], VPCR_DATA_SIZE);
		crypto_shash_final(&desc.shash, digests.digest);
	}

	memcpy(vm->final_hash, digests.digest, VPCR_DATA_SIZE);


	return rc;
}


static int vpcr_bind(void) {
	struct VM_content *vm = NULL;
	struct rhashtable_iter iter;

	struct tpm_digest digests;
	struct {
		struct shash_desc shash;
		char ctx[crypto_shash_descsize_length];
	} desc;
	digests.alg_id=tpm_hash_algo;


	desc.shash.tfm = ima_shash_tfm;

	memset(digests.digest, 0x00, VPCR_DATA_SIZE);

	rcu_read_lock();
	rhashtable_walk_enter(&container_objects, &iter);
	rhashtable_walk_start(&iter);
	while ((vm = rhashtable_walk_next(&iter)) != NULL) {
		crypto_shash_init(&desc.shash);
		crypto_shash_update(&desc.shash, digests.digest, VPCR_DATA_SIZE);

		crypto_shash_update(&desc.shash, vm->final_hash, VPCR_DATA_SIZE);
		crypto_shash_final(&desc.shash, digests.digest);

	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	rcu_read_unlock();

	pcr_read(15, &history_15);
	pcr_extend(&digests, 15);

	return 0;
}


static int vpcr_vmg_bind(void) {
	struct VM_content *vm = NULL;
	struct rhashtable_iter iter;

	struct tpm_digest digests;
	struct {
		struct shash_desc shash;
		char ctx[crypto_shash_descsize_length];
	} desc;
	digests.alg_id=tpm_hash_algo;


	desc.shash.tfm = ima_shash_tfm;

	memset(digests.digest, 0x00, VPCR_DATA_SIZE);

	rcu_read_lock();
	rhashtable_walk_enter(&vmg_objects, &iter);
	rhashtable_walk_start(&iter);
	while ((vm = rhashtable_walk_next(&iter)) != NULL) {
		crypto_shash_init(&desc.shash);
		crypto_shash_update(&desc.shash, digests.digest, VPCR_DATA_SIZE);

		crypto_shash_update(&desc.shash, vm->final_hash, VPCR_DATA_SIZE);
		crypto_shash_final(&desc.shash, digests.digest);

	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	rcu_read_unlock();

	pcr_read(11, &history_11);
	pcr_extend(&digests, 11);

	return 0;
}


static int permall_bind(void) {
	struct VM_content *vm = NULL;
	struct rhashtable_iter iter;

	struct tpm_digest digests;
	struct {
		struct shash_desc shash;
		char ctx[crypto_shash_descsize_length];
	} desc;
	digests.alg_id=tpm_hash_algo;


	desc.shash.tfm = ima_shash_tfm;

	memset(digests.digest, 0x00, VPCR_DATA_SIZE);

	rcu_read_lock();
	rhashtable_walk_enter(&container_objects, &iter);
	rhashtable_walk_start(&iter);
	while ((vm = rhashtable_walk_next(&iter)) != NULL) {
		crypto_shash_init(&desc.shash);
		crypto_shash_update(&desc.shash, digests.digest, VPCR_DATA_SIZE);

		crypto_shash_update(&desc.shash, vm->permanent_state_hash, VPCR_DATA_SIZE);
		crypto_shash_final(&desc.shash, digests.digest);

	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	rcu_read_unlock();

	pcr_read(16, &history_16);
	pcr_extend(&digests, 16);

	return 0;
}


static int permall_vmg_bind(void) {
	struct VM_content *vm = NULL;
	struct rhashtable_iter iter;

	struct tpm_digest digests;
	struct {
		struct shash_desc shash;
		char ctx[crypto_shash_descsize_length];
	} desc;
	digests.alg_id=tpm_hash_algo;


	desc.shash.tfm = ima_shash_tfm;

	memset(digests.digest, 0x00, VPCR_DATA_SIZE);

	rcu_read_lock();
	rhashtable_walk_enter(&vmg_objects, &iter);
	rhashtable_walk_start(&iter);
	while ((vm = rhashtable_walk_next(&iter)) != NULL) {
		crypto_shash_init(&desc.shash);
		crypto_shash_update(&desc.shash, digests.digest, VPCR_DATA_SIZE);

		crypto_shash_update(&desc.shash, vm->permanent_state_hash, VPCR_DATA_SIZE);
		crypto_shash_final(&desc.shash, digests.digest);

	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	rcu_read_unlock();

	pcr_read(12, &history_12);
	pcr_extend(&digests, 12);

	return 0;
}


/*
 * Function used to write the hash value into the specified PCR.
 */
static int pcr_extend(struct tpm_digest *digests, u32 pcr) {
	int result = 0;
	int i = 0;

	if (!tpm_chip_info){
		return result;
	}

	for (i = 0; i < tpm_chip_info->nr_allocated_banks; i++){
		memcpy(digests_csma[i].digest, digests->digest, VPCR_DATA_SIZE);
	}

	result = tpm_pcr_extend(tpm_chip_info, pcr, digests_csma);
	if (result != 0)
		pr_err("Error Communicating to TPM chip, result: %d\n", result);
	return result;
}



/*
 * Function used to read a value from the specified PCR.
 */
//static int pcr_read(int index, u8 *value) {
static int pcr_read(u32 index, struct tpm_digest *digests) {
	int result = 0;
	struct tpm_digest d = { .alg_id = tpm_hash_algo, .digest = {0} };

	if (!tpm_chip_info){
		return result;
	}

	result = tpm_pcr_read(tpm_chip_info, index, &d);

	memcpy(digests->digest, d.digest, VPCR_DATA_SIZE);

	if (result != 0)
		pr_err("IMA: Error Communicating to TPM chip, result: %d\n",
				result);
	return result;
}



int count_vmg=1;
struct rhashtable_iter iter_vmg;
/*
 * Starts a session and takes a position as an argument, returning an iterator which will start reading at that position
 * returns each element of the measurement list
 */
static void *vpcr_vmg_file_start(struct seq_file *m, loff_t *pos){
	/* we need a lock since pos could point beyond last element */

	if (!*pos){
		return SEQ_START_TOKEN;
	}

	rcu_read_lock();
	rhashtable_walk_enter(&vmg_objects, &iter_vmg);
	rhashtable_walk_start(&iter_vmg);

	if(*pos < count_vmg){
		rcu_read_unlock();
		return &iter_vmg;

	}else{
		return NULL;
	}


	rcu_read_unlock();

	return NULL;

}

/*
 * Returns the next element (entry) of sequence
 */


static void *vpcr_vmg_file_next(struct seq_file *m, void *v, loff_t *pos){
	struct VM_content *qe = v;

	(*pos)++;
	if (*pos >= count_vmg){
		return NULL;
	}else{
		return qe;

	}

	//return qe;
	return (count_vmg > 1) ? NULL : qe;


}

/*
 * The vpcr_file_show() function should format the object currently pointed to by the iterator for output
 */
int vpcr_vmg_file_show(struct seq_file *m, void *v){
	int i;
	struct VM_content *vm;

	if(v == SEQ_START_TOKEN){
		seq_puts(m, "previous_PCR11 ");
		for (i = 0; i < VPCR_DATA_SIZE; i ++) {
			seq_printf(m, "%02x", history_11.digest[i]);
		}
		seq_puts(m, "\n");
	}
	rcu_read_lock();
	rhashtable_walk_enter(&vmg_objects, &iter_vmg);
	rhashtable_walk_start(&iter_vmg);
	while ((vm = rhashtable_walk_next(&iter_vmg)) != NULL) {
		rcu_read_unlock();

		seq_printf(m, "%s ", vm->VMID);

		for (i = 0; i < VPCR_DATA_SIZE; i++) {
			seq_printf(m, "%02X", vm->final_hash[i]);

		}
		seq_puts(m, "\n");

	}
	rcu_read_unlock();


	return 0;

}






int count=1;
struct rhashtable_iter iter;
/*
 * Starts a session and takes a position as an argument, returning an iterator which will start reading at that position
 * returns each element of the measurement list
 */
static void *vpcr_file_start(struct seq_file *m, loff_t *pos){
	/* we need a lock since pos could point beyond last element */

	if (!*pos){
		return SEQ_START_TOKEN;
	}

	rcu_read_lock();
	rhashtable_walk_enter(&container_objects, &iter);
	rhashtable_walk_start(&iter);

	if(*pos < count){
		rcu_read_unlock();
		return &iter;

	}else{
		return NULL;
	}


	rcu_read_unlock();

	return NULL;

}


/*
 * Returns the next element (entry) of sequence
 */


static void *vpcr_file_next(struct seq_file *m, void *v, loff_t *pos){
	struct VM_content *qe = v;

	(*pos)++;
	if (*pos >= count){
		return NULL;
	}else{
		return qe;

	}

	//return qe;
	return (count > 1) ? NULL : qe;


}


/*
 * The vpcr_file_show() function should format the object currently pointed to by the iterator for output
 */
int vpcr_file_show(struct seq_file *m, void *v){
	int i;
	struct VM_content *vm;

	if(v == SEQ_START_TOKEN){
		seq_puts(m, "previous_PCR15 ");
		for (i = 0; i < VPCR_DATA_SIZE; i ++) {
			seq_printf(m, "%02x", history_15.digest[i]);
		}
		seq_puts(m, "\n");
	}
	rcu_read_lock();
	rhashtable_walk_enter(&container_objects, &iter);
	rhashtable_walk_start(&iter);
	while ((vm = rhashtable_walk_next(&iter)) != NULL) {
		rcu_read_unlock();

		seq_printf(m, "%s ", vm->VMID);

		for (i = 0; i < VPCR_DATA_SIZE; i++) {
			seq_printf(m, "%02X", vm->final_hash[i]);

		}
		seq_puts(m, "\n");

	}
	rcu_read_unlock();


	return 0;

}

/*
 * The vpcr_file_show() function should format the object currently pointed to by the iterator for output
 */
int permall_file_show(struct seq_file *m, void *v){
	int i;
	struct VM_content *vm;

	if(v == SEQ_START_TOKEN){
		seq_puts(m, "previous_PCR16 ");
		for (i = 0; i < VPCR_DATA_SIZE; i ++) {
			seq_printf(m, "%02x", history_12.digest[i]);
		}
		seq_puts(m, "\n");
	}
	rcu_read_lock();
	rhashtable_walk_enter(&container_objects, &iter);
	rhashtable_walk_start(&iter);
	while ((vm = rhashtable_walk_next(&iter)) != NULL) {
		rcu_read_unlock();

		seq_printf(m, "%s ", vm->VMID);

		for (i = 0; i < VPCR_DATA_SIZE; i++) {
			seq_printf(m, "%02X", vm->permanent_state_hash[i]);

		}
		seq_puts(m, "\n");

	}
	rcu_read_unlock();


	return 0;

}

/*
 * The vpcr_file_stop function closes a session; its job is to clean up
 */
static void vpcr_file_stop(struct seq_file *m, void *v){
}

/*
 * The vpcr_file_stop function closes a session; its job is to clean up
 */
static void vpcr_vmg_file_stop(struct seq_file *m, void *v){
}

/*
 * Open the file with the vpcr's values
 */
static int permall_file_open(struct inode *inode, struct file *file){

	int ret = -1;
	ret = seq_open(file, &permall_file_seqops);
	if(ret != 0)
		return ret;

	return 0;
}

/*
 * Open the file with the vpcr's values
 */
static int vpcr_file_open(struct inode *inode, struct file *file){

	int ret = -1;
	ret = seq_open(file, &vpcr_file_seqops);
	if(ret != 0)
		return ret;

	return 0;
}

/*
 * Open the file with the vpcr's values
 */
static int vpcr_vmg_file_open(struct inode *inode, struct file *file){

	int ret = -1;
	ret = seq_open(file, &vpcr_vmg_file_seqops);
	if(ret != 0)
		return ret;

	return 0;
}


/*
 * Starts a session and takes a position as an argument, returning an iterator which will start reading at that position
 * returns each element of the measurement list
 */
static void *ima_ns_measurements_start(struct seq_file *m, loff_t *pos) {

	const unsigned char *cgroup_ns_path;
	struct vPCR_content *qe;
	unsigned long key;
	struct VM_content *vm = NULL;
	loff_t l;

	cgroup_ns_path = m->file->f_path.dentry->d_name.name;

	key = hash(cgroup_ns_path);

	l = *pos;

	vm = rhashtable_lookup_fast(&container_objects, &key, object_params);

	if(vm != NULL) {
		rcu_read_lock();
		list_for_each_entry_rcu(qe, &vm->list, list) {
			if (!l--) {
				rcu_read_unlock();
				return qe;
			}
		}
		rcu_read_unlock();
		return NULL;
	}else{
		return NULL;
	}
}


/*
 * Starts a session and takes a position as an argument, returning an iterator which will start reading at that position
 * returns each element of the measurement list
 */
static void *ima_ns_measurements_vmg_start(struct seq_file *m, loff_t *pos) {

	const unsigned char *cgroup_ns_path;
	struct vPCR_content *qe;
	unsigned long key;
	struct VM_content *vm = NULL;
	loff_t l;

	cgroup_ns_path = m->file->f_path.dentry->d_name.name;

	key = hash(cgroup_ns_path);

	l = *pos;

	vm = rhashtable_lookup_fast(&vmg_objects, &key, object_params);

	if(vm != NULL) {
		rcu_read_lock();
		list_for_each_entry_rcu(qe, &vm->list, list) {
			if (!l--) {
				rcu_read_unlock();
				return qe;
			}
		}
		rcu_read_unlock();
		return NULL;
	}else{
		return NULL;
	}
}



/*
 * Returns the next element (entry) of sequence
 */
static void *ima_ns_measurements_next(struct seq_file *m, void *v, loff_t *pos){
	struct vPCR_content *qe = v;
	struct VM_content *vm = NULL;
	const unsigned char *cgroup_ns_path;
	unsigned long key;

	rcu_read_lock();
	qe = list_entry_rcu(qe->list.next, struct vPCR_content, list);
	rcu_read_unlock();
	(*pos)++;
	cgroup_ns_path = m->file->f_path.dentry->d_name.name;
	key = hash(cgroup_ns_path);

	vm = rhashtable_lookup_fast(&container_objects, &key, object_params);

	return (&qe->list == &vm->list) ? NULL : qe;
}


/*
 * Returns the next element (entry) of sequence
 */
static void *ima_ns_measurements_vmg_next(struct seq_file *m, void *v, loff_t *pos){
	struct vPCR_content *qe = v;
	struct VM_content *vm = NULL;
	const unsigned char *cgroup_ns_path;
	unsigned long key;

	rcu_read_lock();
	qe = list_entry_rcu(qe->list.next, struct vPCR_content, list);
	rcu_read_unlock();
	(*pos)++;
	cgroup_ns_path = m->file->f_path.dentry->d_name.name;
	key = hash(cgroup_ns_path);

	vm = rhashtable_lookup_fast(&vmg_objects, &key, object_params);

	return (&qe->list == &vm->list) ? NULL : qe;
}


/*
 * The ima_measurements_stop function closes a session; its job is to clean up
 */
static void ima_measurements_stop(struct seq_file *m, void *v){
}


/*
 * The ima_measurements_stop function closes a session; its job is to clean up
 */
static void ima_measurements_vmg_stop(struct seq_file *m, void *v){
}


/*
 * The ima_ns_measurements_show() function should format the object currently pointed to by the iterator for output
 */
int ima_ns_measurements_show(struct seq_file *m, void *v) {
	struct vPCR_content *qe = v;
	int i;
	int j;
	for (i = 0; i < 24; i++) {
		for (j = 0; j < VPCR_DATA_SIZE; j++) {
			seq_printf(m, "%02X", qe->pcr[i][j]);
		}
		seq_printf(m, "\n");
	}


	return 0;
}


/*
 * The ima_ns_measurements_show() function should format the object currently pointed to by the iterator for output
 */
int ima_ns_measurements_vmg_show(struct seq_file *m, void *v) {
	struct vPCR_content *qe = v;
	int i;
	int j;
	for (i = 0; i < 24; i++) {
		for (j = 0; j < VPCR_DATA_SIZE; j++) {
			seq_printf(m, "%02X", qe->pcr[i][j]);
		}
		seq_printf(m, "\n");
	}


	return 0;
}


/*
 * Open the file with the measurements of the container
 */
static int ima_ns_measurements_open(struct inode *inode, struct file *file) {
	int ret = -1;

	ret = seq_open(file, &ima_ns_measurements_seqops);
	if(ret != 0)
		return ret;

	return 0;
}


static int ima_ns_measurements_vmg_open(struct inode *inode, struct file *file) {
	int ret = -1;

	ret = seq_open(file, &ima_ns_measurements_vmg_seqops);
	if(ret != 0)
		return ret;

	return 0;
}

uint8_t* datahex(char* string) {
	size_t slength;
	size_t dlength;
	uint8_t* data;
	size_t index;
	char c;
	int value;

	if(string == NULL)
		return NULL;

	slength = strlen(string);
	if((slength % 2) != 0) // must be even
		return NULL;

	dlength = slength / 2;

	data = kmalloc(dlength, GFP_KERNEL);
	memset(data, 0, dlength);

	index = 0;
	while (index < slength) {
		c = string[index];
		value = 0;
		if(c >= '0' && c <= '9')
			value = (c - '0');
		else if (c >= 'A' && c <= 'F')
			value = (10 + (c - 'A'));
		else if (c >= 'a' && c <= 'f')
			value = (10 + (c - 'a'));
		else {
			kfree(data);
			return NULL;
		}

		data[(index/2)] += value << (((index + 1) % 2) * 4);

		index++;
	}

	return data;
}

struct VM_content *get_init_vm(const unsigned char *VMID){
	unsigned long key;
	struct VM_content *vm;
	struct vPCR_content *vpcr_content;
	int i;

	key = hash(VMID);

	vm = NULL;
	vm = rhashtable_lookup_fast(&container_objects, &key, object_params);

	if(vm!=NULL){
		return vm;
	}else{

		vm = (struct VM_content*) kmalloc(sizeof(*vm), GFP_KERNEL);
		vm->key = key;
		vm->VMID = kmalloc(PATH_MAX, GFP_KERNEL);
		strcpy(vm->VMID, VMID);
		INIT_LIST_HEAD(&vm->list);

		vpcr_content = (struct vPCR_content*) kmalloc(sizeof(*vpcr_content), GFP_KERNEL);

		for (i = 0; i < 24; i++) {
			memset(vpcr_content->pcr[i], 0x00, VPCR_DATA_SIZE);
		}

		memset(vm->permanent_state_hash, 0x00, VPCR_DATA_SIZE);

		list_add_tail(&vpcr_content->list, &vm->list);
		calc_vpcr_digest(vm);
		vm->container_file = securityfs_create_file(VMID, S_IWUSR |S_IRUSR| S_IWGRP| S_IRGRP, vmaas_dir, NULL, &ima_ns_measurements_ops);

		rhashtable_lookup_get_insert_fast(&container_objects, &vm->head, object_params);
		vpcr_bind();
		permall_bind();
		return vm;
	}
	return NULL;
}


struct VM_content *get_init_vmg(const unsigned char *VMID){
	unsigned long key;
	struct VM_content *vm;
	struct vPCR_content *vpcr_content;
	int i;

	key = hash(VMID);

	vm = NULL;
	vm = rhashtable_lookup_fast(&vmg_objects, &key, object_params);

	if(vm!=NULL){
		return vm;
	}else{

		vm = (struct VM_content*) kmalloc(sizeof(*vm), GFP_KERNEL);
		vm->key = key;
		vm->VMID = kmalloc(PATH_MAX, GFP_KERNEL);
		strcpy(vm->VMID, VMID);
		INIT_LIST_HEAD(&vm->list);

		vpcr_content = (struct vPCR_content*) kmalloc(sizeof(*vpcr_content), GFP_KERNEL);

		for (i = 0; i < 24; i++) {
			memset(vpcr_content->pcr[i], 0x00, VPCR_DATA_SIZE);
		}

		memset(vm->permanent_state_hash, 0x00, VPCR_DATA_SIZE);

		list_add_tail(&vpcr_content->list, &vm->list);
		calc_vpcr_digest(vm);
		vm->container_file = securityfs_create_file(VMID, S_IWUSR |S_IRUSR| S_IWGRP| S_IRGRP, vmaas_vmg_dir, NULL, &ima_ns_measurements_vmg_ops);

		rhashtable_lookup_get_insert_fast(&vmg_objects, &vm->head, object_params);
		vpcr_vmg_bind();
		permall_vmg_bind();
		return vm;
	}
	return NULL;
}


int add_vm(char *result_received){
	printk(KERN_INFO "Entrou o add_vm\n");
	const unsigned char *VMID;
	char *pcr;
	int pcr_int;
	char *vm_pcr;
	struct VM_content *vm;
	int ret;
	uint8_t* digest;

	VMID = strsep(&result_received,"/");
	pcr = strsep(&result_received,"/");
	ret = kstrtoint(pcr, 10, &pcr_int);
	if (ret == 0 && pcr_int >= 0 && pcr_int <= 23 && strlen(result_received) == VPCR_DATA_SIZE * 2){
		vm = get_init_vm(VMID);

		vm_pcr = list_entry_rcu(vm->list.next, struct vPCR_content, list)->pcr[pcr_int];
		digest = datahex(result_received);
		memcpy(vm_pcr, digest, VPCR_DATA_SIZE);
		kfree(digest);
		calc_vpcr_digest(vm);
		vpcr_bind();
		printk(KERN_INFO "FINDOU O ADD_VM\n");
	}
	return ret;
}

int add_vmg(char *result_received){
	const unsigned char *VMID;
	char *pcr;
	int pcr_int;
	char *vm_pcr;
	struct VM_content *vm;
	int ret;
	uint8_t* digest;

	VMID = strsep(&result_received,"/");
	pcr = strsep(&result_received,"/");
	ret = kstrtoint(pcr, 10, &pcr_int);
	if (ret == 0 && pcr_int >= 0 && pcr_int <= 23 && strlen(result_received) == VPCR_DATA_SIZE * 2){
		vm = get_init_vmg(VMID);

		vm_pcr = list_entry_rcu(vm->list.next, struct vPCR_content, list)->pcr[pcr_int];
		digest = datahex(result_received);
		memcpy(vm_pcr, digest, VPCR_DATA_SIZE);
		kfree(digest);
		calc_vpcr_digest(vm);
		vpcr_vmg_bind();
	}
	return ret;
}

int del_vm(char *result_received){
	const unsigned char *VMID;
	unsigned long key;
	struct VM_content *vm;


	VMID = strsep(&result_received,"/");

	key = hash(VMID);

	vm = NULL;
	vm = rhashtable_lookup_fast(&container_objects, &key, object_params);
	if(vm!=NULL){
		securityfs_remove(vm->container_file);
		kfree(list_entry_rcu(vm->list.next, struct vPCR_content, list));
		rhashtable_remove_fast(&container_objects, &vm->head, object_params);
		kfree(vm);
		vpcr_bind();

	}
	return 0;
}

int migrate_vm(char *result_received){
	const unsigned char *VMID;
	struct VM_content *vm;
	unsigned long key;
	char *pcr_value;
	struct vPCR_content *vpcr_content;
	uint8_t* digest;
	char *vm_pcr;
	int i;

	VMID = strsep(&result_received,"/");
	key = hash(VMID);
	vm = rhashtable_lookup_fast(&container_objects, &key, object_params);

	if(vm != NULL){
		vpcr_content = list_entry_rcu(vm->list.next, struct vPCR_content, list);

		for (i = 0; i < 24; i++) {
			pcr_value = strsep(&result_received,"\n");
			if(! vpcr_content->pcr[i]){
				vm_pcr = list_entry_rcu(vm->list.next, struct vPCR_content, list)->pcr[i];
				digest = datahex(pcr_value);
				memcpy(vm_pcr, digest, VPCR_DATA_SIZE);
				kfree(digest);
			}
		}

		calc_vpcr_digest(vm);
		vpcr_bind();
		permall_bind();

	}else{
		vm = (struct VM_content*) kmalloc(sizeof(*vm), GFP_KERNEL);
		vm->key = key;
		vm->VMID = kmalloc(PATH_MAX, GFP_KERNEL);
		strcpy(vm->VMID, VMID);
		INIT_LIST_HEAD(&vm->list);

		vpcr_content = (struct vPCR_content*) kmalloc(sizeof(*vpcr_content), GFP_KERNEL);

		for (i = 0; i < 24; i++) {
			memset(vpcr_content->pcr[i], 0x00, VPCR_DATA_SIZE);

			pcr_value = strsep(&result_received,"\n");
			vm_pcr = vpcr_content->pcr[i];
			digest = datahex(pcr_value);
			memcpy(vm_pcr, digest, VPCR_DATA_SIZE);
			kfree(digest);
		}

		memset(vm->permanent_state_hash, 0x00, VPCR_DATA_SIZE);

		list_add_tail(&vpcr_content->list, &vm->list);
		calc_vpcr_digest(vm);
		vm->container_file = securityfs_create_file(VMID, S_IWUSR |S_IRUSR| S_IWGRP| S_IRGRP, vmaas_dir, NULL, &ima_ns_measurements_ops);

		rhashtable_lookup_get_insert_fast(&container_objects, &vm->head, object_params);

		vpcr_bind();
		permall_bind();
	}
	return 0;
}

int add_permanent_state(char *result_received){
	const unsigned char *VMID;
	struct VM_content *vm;
	uint8_t* digest;

	VMID = strsep(&result_received,"/");
	vm = get_init_vm(VMID);

	digest = datahex(result_received);
	memcpy(vm->permanent_state_hash, digest, VPCR_DATA_SIZE);
	kfree(digest);
	permall_bind();
	return 0;
}

int add_snapshot(char *result_received){
	const unsigned char *VMID;
	struct VM_content *vm;
	unsigned long key;
	char *pcr_value;
	struct vPCR_content *vpcr_content;
	uint8_t* digest;
	char *vm_pcr;
	int i;

	VMID = strsep(&result_received,"/");
	key = hash(VMID);
	vm = rhashtable_lookup_fast(&container_objects, &key, object_params);

	if(vm != NULL){

		vpcr_content = list_entry_rcu(vm->list.next, struct vPCR_content, list);

		for (i = 0; i < 24; i++) {
			memset(vpcr_content->pcr[i], 0x00, VPCR_DATA_SIZE);

			pcr_value = strsep(&result_received,"\n");
			vm_pcr = vpcr_content->pcr[i];
			digest = datahex(pcr_value);
			memcpy(vm_pcr, digest, VPCR_DATA_SIZE);
			kfree(digest);
		}

		calc_vpcr_digest(vm);
		vpcr_bind();
		permall_bind();

	}else{
		vm = (struct VM_content*) kmalloc(sizeof(*vm), GFP_KERNEL);
		vm->key = key;
		vm->VMID = kmalloc(PATH_MAX, GFP_KERNEL);
		strcpy(vm->VMID, VMID);
		INIT_LIST_HEAD(&vm->list);

		vpcr_content = (struct vPCR_content*) kmalloc(sizeof(*vpcr_content), GFP_KERNEL);

		for (i = 0; i < 24; i++) {
			memset(vpcr_content->pcr[i], 0x00, VPCR_DATA_SIZE);

			pcr_value = strsep(&result_received,"\n");
			vm_pcr = vpcr_content->pcr[i];
			digest = datahex(pcr_value);
			memcpy(vm_pcr, digest, VPCR_DATA_SIZE);
			kfree(digest);
		}

		memset(vm->permanent_state_hash, 0x00, VPCR_DATA_SIZE);

		list_add_tail(&vpcr_content->list, &vm->list);
		calc_vpcr_digest(vm);
		vm->container_file = securityfs_create_file(VMID, S_IWUSR |S_IRUSR| S_IWGRP| S_IRGRP, vmaas_dir, NULL, &ima_ns_measurements_ops);

		rhashtable_lookup_get_insert_fast(&container_objects, &vm->head, object_params);

		vpcr_bind();
		permall_bind();
	}
	return 0;

}

static void hello_nl_recv_msg(struct sk_buff *skb) {

	struct nlmsghdr *nlh;
	int pid;
	struct sk_buff *skb_out;
	int msg_size;
	char *msg="RECEIVED";
	int res;
	char *api_route;
	char *result_received;

	msg_size=strlen(msg);

	nlh=(struct nlmsghdr*)skb->data;
	printk(KERN_INFO "Netlink received msg payload: %s\n",(char*)nlmsg_data(nlh));
	pid = nlh->nlmsg_pid; /*pid of sending process */

	result_received = kmalloc(PATH_MAX, GFP_KERNEL);
	snprintf(result_received, PATH_MAX,"%s",((char *)nlmsg_data(nlh)));
	api_route = strsep(&result_received,"/");

	if(strcmp("ADD",api_route) == 0){
		// ADD/VMID/PCRNUM/PCRVAL
		printk(KERN_INFO "CHAMOU ADD\n");
		add_vm(result_received);
	}else if(strcmp("ADD-VMG",api_route) == 0){
		// ADD/VMID/PCRNUM/PCRVAL
		printk(KERN_INFO "CHAMOU ADD\n");
		add_vmg(result_received);
	} else if(strcmp("DEL", api_route) == 0){
		// DEL/VMID
		del_vm(result_received);
	} else	if(strcmp("MIGRATE", api_route) == 0){
		// MIGRATE/VMID/PCRVAL0\nPCRVAL1\nPCRVAL2\n...PCRVAL23\n
		migrate_vm(result_received);
	} else	if(strcmp("PERMANENT-STATE", api_route) == 0){
		// PERMANENT-STATE/VMID/VAL
		add_permanent_state(result_received);
	} else	if(strcmp("SNAPSHOT", api_route) == 0){
		// SNAPSHOT/VMID/PCRVAL0\nPCRVAL1\nPCRVAL2\n...PCRVAL23\n
		add_snapshot(result_received);
	}

	skb_out = nlmsg_new(msg_size,0);

	if(!skb_out){

		printk(KERN_ERR "Failed to allocate new skb\n");
		return;

	}
	nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,msg_size,0);
	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
	strncpy(nlmsg_data(nlh),msg,msg_size);

	res=nlmsg_unicast(nl_sk,skb_out,pid);

	if(res<0){
		printk(KERN_INFO "Error while sending back to user\n");
	}

}

static int ima_init_digests(void){
	int i;

	if (!tpm_chip_info)
		return 0;

	digests_csma = kcalloc(tpm_chip_info->nr_allocated_banks, sizeof(*digests_csma),
			GFP_NOFS);
	if (!digests_csma)
		return -ENOMEM;

	for (i = 0; i < tpm_chip_info->nr_allocated_banks; i++){
		digests_csma[i].alg_id = tpm_chip_info->allocated_banks[i].alg_id;
	}

	return 0;
}


static int __init vmaas_module_init(void) {

	struct netlink_kernel_cfg cfg = {
		.input = hello_nl_recv_msg,
	};

	printk(KERN_INFO "Entering VMAAS module\n");

	hash_setup(ima_hash);

	rhashtable_init(&container_objects, &object_params);
	rhashtable_init(&vmg_objects, &object_params);

	vmaas_dir = securityfs_create_dir("vmaas", NULL);
	vmaas_vmg_dir = securityfs_create_dir("vmaasvmg", NULL);
	vpcr_vmg_file = securityfs_create_file("vpcrvmg", S_IWUSR |S_IRUSR| S_IWGRP| S_IRGRP, vmaas_vmg_dir, NULL, &vpcr_vmg_file_ops);
	permall_vmg_file = securityfs_create_file("permallvmg", S_IWUSR |S_IRUSR| S_IWGRP| S_IRGRP, vmaas_vmg_dir, NULL, &permall_file_ops);

	vpcr_file = securityfs_create_file("vpcr", S_IWUSR |S_IRUSR| S_IWGRP| S_IRGRP, vmaas_dir, NULL, &vpcr_file_ops);
	permall_file = securityfs_create_file("permall", S_IWUSR |S_IRUSR| S_IWGRP| S_IRGRP, vmaas_dir, NULL, &permall_file_ops);

	nl_sk = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);


	if(!nl_sk)
	{

		printk(KERN_ALERT "Error creating socket.\n");
		return -10;

	}
	ima_shash_tfm = crypto_alloc_shash(hash_algo_name[ima_hash_algo], 0, 0);
	crypto_shash_descsize_length = crypto_shash_descsize(ima_shash_tfm);

	tpm_chip_info = tpm_default_chip();
	if (!tpm_chip_info){
		pr_info("No TPM chip found, activating TPM-bypass!\n");
	}
	ima_init_digests();
	pcr_read(11, &history_11);
	pcr_read(12, &history_12);

	memset(last_vpcr_extend.digest, 0x00, VPCR_DATA_SIZE);
	memset(last_permamall_extend.digest, 0x00, VPCR_DATA_SIZE);

	pcr_extend(&last_vpcr_extend, 15);
	pcr_extend(&last_permamall_extend, 16);

	return 0;
}

static void __exit vmaas_module_exit(void) {
	struct VM_content *vm = NULL;

	printk(KERN_INFO "Exiting VMAAS module\n");
	netlink_kernel_release(nl_sk);

	rhashtable_walk_enter(&container_objects, &iter);
	rhashtable_walk_start(&iter);
	while ((vm = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(vm)){
			continue;
		}
		securityfs_remove(vm->container_file);
		kfree(list_entry_rcu(vm->list.next, struct vPCR_content, list));
		rhashtable_remove_fast(&container_objects, &vm->head, object_params);
		kfree(vm);
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);


	rhashtable_walk_enter(&vmg_objects, &iter_vmg);
	rhashtable_walk_start(&iter_vmg);
	while ((vm = rhashtable_walk_next(&iter_vmg)) != NULL) {
		if (IS_ERR(vm)){
			continue;
		}
		securityfs_remove(vm->container_file);
		kfree(list_entry_rcu(vm->list.next, struct vPCR_content, list));
		rhashtable_remove_fast(&vmg_objects, &vm->head, object_params);
		kfree(vm);
	}
	rhashtable_walk_stop(&iter_vmg);
	rhashtable_walk_exit(&iter_vmg);


	vpcr_bind();
	permall_bind();

	vpcr_vmg_bind();
	permall_vmg_bind();

	securityfs_remove(vpcr_file);
	securityfs_remove(permall_file);
	securityfs_remove(vmaas_dir);

	securityfs_remove(vpcr_vmg_file);
	securityfs_remove(permall_vmg_file);
	securityfs_remove(vmaas_vmg_dir);
}

module_init(vmaas_module_init);
module_exit(vmaas_module_exit);
