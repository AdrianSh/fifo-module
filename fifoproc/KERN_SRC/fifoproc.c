#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
/* #include <linux/ftrace.h>	Debug con ftrace */
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/kfifo.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fifoproc :) Practica 4");
MODULE_AUTHOR("Adrian E. Sanchez H");

struct proc_dir_entry *fifo_dir = NULL; // Entrada /proc/fifo
static struct proc_dir_entry *control_proc_entry; // Entrada /proc/fifo/control

static ushort max_entries = 4;
static ushort max_size = 64;
#define INPUT_FIFOCONTROL_BUFFER_LENGTH 266

typedef struct {
	char * fileName;
	int cons_count; // = 0;
	int prod_count; // = 0;
	struct kfifo cbuffer; // Almacenamiento temporal
	struct semaphore mtx; // Para proteger el buffer y los contadores (semaforo inicializado a 1)
	struct semaphore prod, cons; // Para bloquear al productor y al consumidor (Semaforo inicializado a 0, contador de procesos esperando)
	int nr_prod_waiting; // = 0; // Número de procesos productores esperando
	int nr_cons_waiting; // = 0; // Número de procesos consumidores esperando
} proc_required_data;

typedef struct {
	proc_required_data * data;
	char * fileName;
} proc_entry_data;

static proc_entry_data * default_proc_entry; // Entrada /proc/fifo/default

struct list_head entrylist;
typedef struct {
	proc_entry_data * data;
	struct list_head links;
} proclist_item;
DEFINE_SPINLOCK(sp_entrylist);
int entrylist_size = 0;

static void deleteProc(proc_entry_data * entryData);

void clear_list(struct list_head *list) {
	proclist_item *aux, *elem = NULL;

	spin_lock(&sp_entrylist);
	list_for_each_entry_safe(elem, aux, list, links) {
		spin_unlock(&sp_entrylist);
		/* Eliminino lo correspondiente dentro de data */
		deleteProc(elem->data);

		spin_lock(&sp_entrylist);
		list_del(&(elem->links));
		entrylist_size--;
		vfree(elem);
	}
	spin_unlock(&sp_entrylist);
}

void add_item_list(struct list_head *list, proc_entry_data *data) {
	proclist_item *item;
	item = vmalloc(sizeof(proclist_item));
	item->data = data;

	spin_lock(&sp_entrylist);
	list_add_tail(&(item->links), list);
	entrylist_size++;
	spin_unlock(&sp_entrylist);
}

int check_exist_item_list(struct list_head *list, char * fileName){
	proclist_item *aux, *elem = NULL;
	int ret = -1;

	spin_lock(&sp_entrylist);
	list_for_each_entry_safe(elem, aux, list, links) {
		if (strcmp(elem->data->fileName, fileName) == 0) {
			printk(KERN_INFO "FifoProc-check-exist-item   %s existia %s, %i!\n", fileName, elem->data->fileName, strcmp(elem->data->fileName, fileName));
			ret = 0;
		}
	}
	spin_unlock(&sp_entrylist);

	return ret;
}

void remove_items_list(struct list_head *list, char * fileName) {
	proclist_item *aux, *elem = NULL;

	spin_lock(&sp_entrylist);
	list_for_each_entry_safe(elem, aux, list, links) {
		if (strcmp(elem->data->fileName, fileName) == 0) {
			spin_unlock(&sp_entrylist);
			/* Eliminino lo correspondiente dentro de data */
			deleteProc(elem->data);

			spin_lock(&sp_entrylist);
			list_del(&(elem->links));
			entrylist_size--;
			vfree(elem);
		}
	}
	spin_unlock(&sp_entrylist);
}

static int fifoproc_open(struct inode *inode, struct file *file) {
	proc_required_data* private_data = (proc_required_data*) PDE_DATA(file->f_inode);

	if (down_interruptible(&(private_data->mtx))) {
		return -EINTR;
	} // Para acceder a contadores

	if (file->f_mode & FMODE_READ) {
		printk(KERN_INFO "FifoProc: Ha ingresado un consumidor.\n");

		// Modo lectura -> CONSUMIDOR
		private_data->cons_count++;

		// Si tengo productores esperando
		if (private_data->nr_prod_waiting > 0) {
			up(&(private_data->prod)); // Despierto a un productor
			private_data->nr_prod_waiting--;
		}

		while (private_data->prod_count <= 0) {
			private_data->nr_cons_waiting++; // Consumidor esperando
			up(&(private_data->mtx)); /* "Libera" el mutex */
			printk(KERN_INFO "FifoProc: Consumidor esperando.\n");

			/* Se bloquea en la cola */
			if (down_interruptible(&(private_data->cons))) {
				down(&(private_data->mtx));
				private_data->nr_cons_waiting--;
				private_data->cons_count--;
				up(&(private_data->mtx));
				return -EINTR;
			}

			/* "Adquiere" el mutex */
			if (down_interruptible(&(private_data->mtx)))
				return -EINTR;
		}
	} else {
		printk(KERN_INFO "FifoProc: Ha ingresado un productor.\n");

		// PRODUCTOR
		private_data->prod_count++;

		// Si tengo consumidores esperando
		if (private_data->nr_cons_waiting > 0) {
			up(&(private_data->cons));
			private_data->nr_cons_waiting--;
		}

		while (private_data->cons_count <= 0) {
			private_data->nr_prod_waiting++; // Productor esperando
			up(&(private_data->mtx)); /* "Libera" el mutex */
			printk(KERN_INFO "FifoProc: Productor esperando.\n");

			/* Se bloquea en la cola */
			if (down_interruptible(&(private_data->prod))) {
				down(&(private_data->mtx));
				private_data->nr_prod_waiting--;
				private_data->prod_count--;
				up(&(private_data->mtx));
				return -EINTR;
			}

			/* "Adquiere" el mutex */
			if (down_interruptible(&(private_data->mtx)))
				return -EINTR;
		}
	}

	up(&(private_data->mtx));

	return 0;
}

static ssize_t fifoproc_write(struct file *file, const char __user *buf,
		size_t len, loff_t *off) {
	proc_required_data* private_data = (proc_required_data*) PDE_DATA(file->f_inode);

	char kbuffer[max_size];

	if (len > max_size || len > max_size) {
		return -ENOSPC;
	}
	if (copy_from_user(kbuffer, buf, len)) {
		return -ENOSPC;
	}

	/* "Adquiere" el mutex */
	if (down_interruptible(&(private_data->mtx)))
		return -EINTR;

	/* Esperar hasta que haya hueco para insertar (debe haber consumidores) */
	while (kfifo_avail(&(private_data->cbuffer)) < len
			&& private_data->cons_count > 0) {
		private_data->nr_prod_waiting++;
		up(&(private_data->mtx)); /* "Libera" el mutex */
		/* Se bloquea en la cola */
		if (down_interruptible(&(private_data->prod))) {
			down(&(private_data->mtx));
			private_data->nr_prod_waiting--;
			up(&(private_data->mtx));
			return -EINTR;
		}
		/* "Adquiere" el mutex */
		if (down_interruptible(&(private_data->mtx)))
			return -EINTR;
	}

	/* Detectar fin de comunicación por error (consumidor cierra FIFO antes) */
	if (private_data->cons_count == 0) {
		up(&(private_data->mtx)); // unlock
		return -EPIPE;
	}

	// Escribe en el buffer
	kfifo_in(&(private_data->cbuffer), kbuffer, len);

	/* Despertar a posible consumidor bloqueado */
	if (private_data->nr_cons_waiting > 0) {
		up(&(private_data->cons));
		private_data->nr_cons_waiting--;
	}

	up(&(private_data->mtx)); // unlock

	return len;
}

static ssize_t fifoproc_read(struct file *file, char __user *buf, size_t len,
		loff_t *off) {
	proc_required_data* private_data = (proc_required_data*) PDE_DATA(file->f_inode);

	int bytes_extracted;
	char kbuffer[max_size];

	if (len > max_size || len > max_size) {
		return -ENOSPC;
	}

	/* "Adquiere" el mutex */
	if (down_interruptible(&(private_data->mtx)))
		return -EINTR;

	/* espera a tener lo suficiente para leer */
	while (kfifo_len(&(private_data->cbuffer)) < len
			&& private_data->prod_count > 0) {
		private_data->nr_cons_waiting++;
		up(&(private_data->mtx)); /* "Libera" el mutex */
		/* Se bloquea en la cola */
		if (down_interruptible(&(private_data->cons))) {
			down(&(private_data->mtx));
			private_data->nr_cons_waiting--;
			up(&(private_data->mtx));
			return -EINTR;
		}
		/* "Adquiere" el mutex */
		if (down_interruptible(&(private_data->mtx)))
			return -EINTR;

	}

	/* Detectar fin de comunicación por las buenas */
	if (kfifo_is_empty(&(private_data->cbuffer)) && private_data->prod_count
			== 0) {
		up(&(private_data->mtx));
		return 0;
	}

	// Lee del buffer
	bytes_extracted = kfifo_out(&(private_data->cbuffer), &kbuffer, len);

	// Despierta un productor
	if (private_data->nr_prod_waiting > 0) {
		up(&(private_data->prod));
		private_data->nr_prod_waiting--;
	}

	up(&(private_data->mtx)); // unlock

	if (bytes_extracted != len)
		return -EINVAL;

	// Envio al consumidor lo leido
	if (copy_to_user(buf, kbuffer, len))
		return -EFAULT;

	return len;
}

static int fifoproc_release(struct inode * inodo, struct file * file) {
	proc_required_data* private_data = (proc_required_data*) PDE_DATA(file->f_inode);

	/* Tratamiento de señales */

	// Despertar el otro
	/* "Adquiere" el mutex */
	if (down_interruptible(&(private_data->mtx)))
		return -EINTR;

	if (file->f_mode & FMODE_READ) {
		// Modo lectura -> CONSUMIDOR
		private_data->cons_count--;
		printk(
				KERN_INFO "FifoProc: Ha salido un consumidor (%i Consumidores y %i Productores)\n",
				private_data->cons_count, private_data->prod_count);
		up(&(private_data->prod));
	} else {
		private_data->prod_count--;
		printk(
				KERN_INFO "FifoProc: Ha salido un productor (%i Productores y %i Consumidores)\n",
				private_data->prod_count, private_data->cons_count);
		up(&(private_data->cons));
	}

	if (private_data->cons_count == 0 && private_data->prod_count == 0) {
		kfifo_reset(&(private_data->cbuffer));
	}

	up(&(private_data->mtx)); // unlock

	return 0;
}

static const struct file_operations proc_entry_fops = { .read = fifoproc_read,
		.write = fifoproc_write, .open = fifoproc_open, .release =
				fifoproc_release };

static int createProc(char * entryName, int add_item_to_list) {
	int ret = 0;
	proc_required_data *procItem;
	struct proc_dir_entry *proc_entry;
	proc_entry_data *procEntry;

	procItem = vmalloc(sizeof(proc_required_data));

	printk(KERN_INFO "FifoProc-createProc: inicializando semaforos! %s\n", entryName);
	sema_init(&(procItem->mtx), 1); // Simula mutex
	sema_init(&(procItem->prod), 0); // Cola de espera
	sema_init(&(procItem->cons), 0); // Cola de espera

	printk(KERN_INFO "FifoProc-createProc: inicializando contadores!\n");
	procItem->cons_count = procItem->prod_count = procItem->nr_prod_waiting
			= procItem->nr_cons_waiting = 0;

	printk(KERN_INFO "FifoProc-createProc: inicializando buffer circular!\n");
	ret = kfifo_alloc(&(procItem->cbuffer), max_size, GFP_KERNEL);

	if (ret == 0) {
		printk(KERN_INFO "FifoProc-createProc: inicializando la estructura de proceso!\n");
		procEntry = vmalloc(sizeof(proc_entry_data));

		printk(KERN_INFO "FifoProc-createProc: copiando nombre de entrada: %s! (%p)\n", entryName, entryName);

		procEntry->fileName = entryName;

		printk(KERN_INFO "FifoProc-createProc: asignando datos!\n");
		procEntry->data = procItem;

		printk(KERN_INFO "FifoProc-createProc: registrando en lista!\n");
		if(add_item_to_list == 1)
			add_item_list(&entrylist, procEntry);
		else
			default_proc_entry = procEntry;

		printk(KERN_INFO "FifoProc-Control: Se va crear la entrada de %s\n", procEntry->fileName);

		proc_entry = proc_create_data(procEntry->fileName, 0666, fifo_dir, &proc_entry_fops, procItem);

		if (proc_entry == NULL)
			ret = -ENOMEM;
	} else {
		vfree(procItem);
	}

	return ret;
}

static void deleteProc(proc_entry_data * entryData) {
	kfifo_free(&(entryData->data->cbuffer));
	vfree(entryData->data);
	remove_proc_entry(entryData->fileName, fifo_dir);
	// vfree(entryData->fileName);
	vfree(entryData);
}

static ssize_t fifocontrolwrite(struct file *filp, const char __user *buf,
		size_t len, loff_t *off) {
	char *inputBuffer = NULL;
	char *fileName;
	char operation[8], entryName[256]; // 255 es la longitud maxima para la mayoria de fs
	ssize_t ret = 0;

	if ((*off) > 0) { /* The application can write in this entry just once !! */
		ret = 0;
	} else if (len > INPUT_FIFOCONTROL_BUFFER_LENGTH - 1) {
		printk(KERN_INFO "FifoProc-Control: not enough space!!\n");
		ret = -ENOSPC;
	} else {
		inputBuffer = (char *) vmalloc(INPUT_FIFOCONTROL_BUFFER_LENGTH);
		if (!inputBuffer) {
			ret = -ENOMEM;
		} else {
			if (copy_from_user(&inputBuffer[0], buf, len)) {
				ret = -EFAULT;
			} else {
				sscanf(&inputBuffer[0], "%s %s", operation, entryName);

				*off += len; /* Update the file pointer */
				ret = len;

				if (strlen(entryName) <= 0) {
					printk(
							KERN_INFO "FifoProc-Control: invalid file name! %s\n",
							operation);
					ret = -EINVAL;
				} else if (strcmp(operation, "create") == 0) {
					spin_lock(&sp_entrylist);
					if (entrylist_size < max_entries) {
						spin_unlock(&sp_entrylist);
						printk(
								KERN_INFO "FifoProc-Control: Creando fifo: '%s'\n",
								entryName);

						ret = check_exist_item_list(&entrylist, entryName);
						if(ret < 0){
							fileName = vmalloc(strlen(entryName));
							strcpy(fileName, entryName);
							ret = createProc(fileName, 1);
							printk(KERN_INFO "FifoProc-Control: Proceso de creacion: '%zd'\n", ret);
							ret = len;
						} else {
							printk(KERN_INFO "FifoProc-Control: Ya existia: '%s'\n", entryName);
							ret = -EINVAL;
						}
					} else {
						spin_unlock(&sp_entrylist);
						ret = -ENOMEM;
					}
				} else if (strcmp(operation, "delete") == 0) {
					printk(
							KERN_INFO "FifoProc-Control: Eliminando fifo: '%s'\n",
							entryName);
					remove_items_list(&entrylist, entryName);
				} else {
					printk(
							KERN_INFO "FifoProc-Control: invalid operation! %s\n",
							operation);
					ret = -EINVAL;
				}

				/* inputBuffer[len] = '\0'; // Add the `\0' at the end
				 */
			}
			vfree(inputBuffer);
		}
	}
	return ret;
}

static const struct file_operations control_proc_entry_fops = { .write =
		fifocontrolwrite };

module_param(max_entries, ushort, 0000)
;
MODULE_PARM_DESC(max_entries, "Número máximo de entradas que pueden existir de forma simultánea (sin contar la entrada control).");

module_param(max_size, ushort, 0000)
;
MODULE_PARM_DESC(max_entries, "Tamaño máximo en bytes de buffers circulares asociados a los FIFOs");

int fifo_init(void) {
	int ret = 0;
	char * defaultEntryName = "default";

	if (max_entries < 0 || max_entries > 65535 || max_size < 0 || max_size
			> 65535) // Aunque ya es un unsigned short
		return -EINVAL;

	printk(KERN_INFO "FifoProc: Creando directorio /proc/fifo\n");
	fifo_dir = proc_mkdir("fifo", NULL);
	printk(KERN_INFO "FifoProc: Directorio creado correctamente\n");

	if (fifo_dir == NULL)
		return -ENOMEM;

	ret = createProc(defaultEntryName, 0);
	printk(KERN_INFO "FifoProc: Entrada FIFO por defecto construida.\n");

	if (ret < 0) {
		remove_proc_entry("fifo", NULL);
		return ret;
	}

	control_proc_entry
			= proc_create("control", 0666, fifo_dir, &control_proc_entry_fops);
	if (control_proc_entry == NULL) {
		deleteProc(default_proc_entry);
		remove_proc_entry("fifo", NULL);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&entrylist);

	printk(KERN_INFO "FifoProc: Modulo cargado.\n");

	return ret;
}

void fifo_clean(void) {
	clear_list(&entrylist);
	deleteProc(default_proc_entry);
	remove_proc_entry("control", fifo_dir);
	remove_proc_entry("fifo", NULL);
	printk(KERN_INFO "FifoProc: Modulo descargado.\n");
}

module_init (fifo_init)
;
module_exit (fifo_clean)
;
