#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
/* #include <linux/ftrace.h>	Debug con ftrace */
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/kfifo.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fifoproc :) Practica 4");
MODULE_AUTHOR("Adrian E. Sanchez H");

int prod_count = 0, cons_count = 0;
struct kfifo cbuffer; // Almacenamiento temporal

struct semaphore mtx; // Para proteger el buffer y los contadores (semaforo inicializado a 1)
struct semaphore prod, cons; // Para bloquear al productor y al consumidor (Semaforo inicializado a 0, contador de procesos esperando)
int nr_prod_waiting = 0; // Número de procesos productores esperando
int nr_cons_waiting = 0; // Número de procesos consumidores esperando

struct proc_dir_entry *fifo_dir = NULL; // Entrada /proc/fifo
static struct proc_dir_entry *proc_entry; // Entrada /proc

/* Usamos un buffer de 64 */
#define MAX_CBUFFER_LEN 64
#define MAX_KBUF 64

static int fifoproc_open(struct inode *inode, struct file *file) {
	if (down_interruptible(&mtx)) {
		return -EINTR;
	} // Para acceder a contadores

	if (file->f_mode & FMODE_READ) {
		printk(KERN_INFO "FifoProc: Ha ingresado un consumidor.\n");

		// Modo lectura -> CONSUMIDOR
		cons_count++;

		// Si tengo productores esperando
		if (nr_prod_waiting > 0) {
			up(&prod); // Despierto a un productor
			nr_prod_waiting--;
		}

		while (prod_count <= 0) {
			nr_cons_waiting++; // Consumidor esperando
			up(&mtx); /* "Libera" el mutex */
			printk(KERN_INFO "FifoProc: Consumidor esperando.\n");

			/* Se bloquea en la cola */
			if (down_interruptible(&cons)) {
				down(&mtx);
				nr_cons_waiting--;
				cons_count--;
				up(&mtx);
				return -EINTR;
			}

			/* "Adquiere" el mutex */
			if (down_interruptible(&mtx))
				return -EINTR;
		}
	} else {
		printk(KERN_INFO "FifoProc: Ha ingresado un productor.\n");

		// PRODUCTOR
		prod_count++;

		// Si tengo consumidores esperando
		if (nr_cons_waiting > 0) {
			up(&cons);
			nr_cons_waiting--;
		}

		while (cons_count <= 0) {
			nr_prod_waiting++; // Productor esperando
			up(&mtx); /* "Libera" el mutex */
			printk(KERN_INFO "FifoProc: Productor esperando.\n");

			/* Se bloquea en la cola */
			if (down_interruptible(&prod)) {
				down(&mtx);
				nr_prod_waiting--;
				prod_count--;
				up(&mtx);
				return -EINTR;
			}

			/* "Adquiere" el mutex */
			if (down_interruptible(&mtx))
				return -EINTR;
		}
	}

	up(&mtx);

	return 0;
}

static ssize_t fifoproc_write(struct file *filp, const char __user *buf,
		size_t len, loff_t *off) {
	char kbuffer[MAX_KBUF];

	if (len > MAX_CBUFFER_LEN || len > MAX_KBUF) {
		return -ENOSPC;
	}
	if (copy_from_user(kbuffer, buf, len)) {
		return -ENOSPC;
	}

	/* "Adquiere" el mutex */
	if (down_interruptible(&mtx))
		return -EINTR;

	/* Esperar hasta que haya hueco para insertar (debe haber consumidores) */
	while (kfifo_avail(&cbuffer) < len && cons_count > 0) {
		nr_prod_waiting++;
		up(&mtx); /* "Libera" el mutex */
		/* Se bloquea en la cola */
		if (down_interruptible(&prod)) {
			down(&mtx);
			nr_prod_waiting--;
			up(&mtx);
			return -EINTR;
		}
		/* "Adquiere" el mutex */
		if (down_interruptible(&mtx))
			return -EINTR;
	}

	/* Detectar fin de comunicación por error (consumidor cierra FIFO antes) */
	if (cons_count == 0) {
		up(&mtx); // unlock
		return -EPIPE;
	}

	// Escribe en el buffer
	kfifo_in(&cbuffer,kbuffer,len);

	/* Despertar a posible consumidor bloqueado */
	if (nr_cons_waiting > 0) {
		up(&cons);
		nr_cons_waiting--;
	}

	up(&mtx); // unlock

	return len;
}

static ssize_t fifoproc_read(struct file *filp, char __user *buf, size_t len,
		loff_t *off) {
	int bytes_extracted;
	char kbuffer[MAX_KBUF];

	if (len > MAX_CBUFFER_LEN || len > MAX_KBUF) {
		return -ENOSPC;
	}

	/* "Adquiere" el mutex */
	if (down_interruptible(&mtx))
		return -EINTR;

	/* espera a tener lo suficiente para leer */
	while (kfifo_len(&cbuffer) < len && prod_count > 0) {
		nr_cons_waiting++;
		up(&mtx); /* "Libera" el mutex */
		/* Se bloquea en la cola */
		if (down_interruptible(&cons)) {
			down(&mtx);
			nr_cons_waiting--;
			up(&mtx);
			return -EINTR;
		}
		/* "Adquiere" el mutex */
		if (down_interruptible(&mtx))
			return -EINTR;

	}

	/* Detectar fin de comunicación por las buenas */
	if (kfifo_is_empty(&cbuffer) && prod_count == 0) {
		up(&mtx);
		return 0;
	}

	// Lee del buffer
	bytes_extracted = kfifo_out(&cbuffer, &kbuffer, len);

	// Despierta un productor
	if (nr_prod_waiting > 0) {
		up(&prod);
		nr_prod_waiting--;
	}

	up(&mtx); // unlock

	if (bytes_extracted != len)
		return -EINVAL;

	// Envio al consumidor lo leido
	if (copy_to_user(buf, kbuffer, len))
		return -EFAULT;

	return len;
}

static int fifoproc_release(struct inode * inodo, struct file * file) {
	/* Tratamiento de señales */

	// Despertar el otro
	/* "Adquiere" el mutex */
	if (down_interruptible(&mtx))
		return -EINTR;

	if (file->f_mode & FMODE_READ) {
		// Modo lectura -> CONSUMIDOR
		cons_count--;
		printk(
				KERN_INFO "FifoProc: Ha salido un consumidor (%i Consumidores y %i Productores)\n",
				cons_count, prod_count);
		up(&prod);
	} else {
		prod_count--;
		printk(
				KERN_INFO "FifoProc: Ha salido un productor (%i Productores y %i Consumidores)\n",
				prod_count, cons_count);
		up(&cons);
	}

	if (cons_count == 0 && prod_count == 0) {
		kfifo_reset(&cbuffer);
	}

	up(&mtx); // unlock

	return 0;
}

static const struct file_operations proc_entry_fops = { .read = fifoproc_read,
		.write = fifoproc_write, .open = fifoproc_open, .release =
				fifoproc_release };

int fifo_init(void) {
	int ret = 0;

	fifo_dir = proc_mkdir("fifo", NULL);

	if (!fifo_dir)
		return -ENOMEM;

	proc_entry = proc_create("fifoproc", 0666, fifo_dir, &proc_entry_fops);
	if (proc_entry == NULL) {
		remove_proc_entry("fifo", NULL);
		ret = -ENOMEM;
	} else {
		sema_init(&mtx, 1); // Simula mutex
		sema_init(&prod, 0); // Cola de espera
		sema_init(&cons, 0); // Cola de espera
		nr_prod_waiting = nr_cons_waiting = 0;
		ret = kfifo_alloc(&cbuffer, MAX_CBUFFER_LEN, GFP_KERNEL);
		printk(KERN_INFO "FifoProc: Modulo cargado.\n");
	}

	return ret;
}

void fifo_clean(void) {
	remove_proc_entry("fifoproc", fifo_dir);
	remove_proc_entry("fifo", NULL);
	kfifo_free(&cbuffer);
	printk(KERN_INFO "FifoProc: Modulo descargado.\n");
}

module_init (fifo_init)
;
module_exit (fifo_clean)
;
