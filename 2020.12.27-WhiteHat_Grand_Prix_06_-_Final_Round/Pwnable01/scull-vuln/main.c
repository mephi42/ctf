/*
 * main.c -- the bare scull char module
 *
 * Copyright (C) 2001 Alessandro Rubini and Jonathan Corbet
 * Copyright (C) 2001 O'Reilly & Associates
 *
 * The source code in this file can be freely used, adapted,
 * and redistributed in source or binary form, so long as an
 * acknowledgment appears in derived source files.  The citation
 * should list that the code comes from the book "Linux Device
 * Drivers" by Alessandro Rubini and Jonathan Corbet, published
 * by O'Reilly & Associates.   No warranty is attached;
 * we cannot take responsibility for errors or fitness for use.
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h>   /* printk() */
#include <linux/slab.h>     /* kmalloc() */
#include <linux/fs.h>       /* everything... */
#include <linux/errno.h>    /* error codes */
#include <linux/types.h>    /* size_t */
#include <linux/proc_fs.h>
#include <linux/fcntl.h>    /* O_ACCMODE */
#include <linux/seq_file.h>
#include <linux/cdev.h>

#include <linux/uaccess.h>  /* copy_*_user */

#include "scull.h"      /* local definitions */
#include "access_ok_version.h"
#include "proc_ops_version.h"

#define KMALLOC_GFP_MASK GFP_KERNEL
/*
 * Our parameters which can be set at load time.
 */

int scull_major =   SCULL_MAJOR;
int scull_minor =   0;
int scull_nr_devs = SCULL_NR_DEVS;  /* number of bare scull devices */
int scull_quantum = SCULL_QUANTUM;
int scull_qset =    SCULL_QSET;

module_param(scull_major, int, S_IRUGO);
module_param(scull_minor, int, S_IRUGO);
module_param(scull_nr_devs, int, S_IRUGO);
module_param(scull_quantum, int, S_IRUGO);
module_param(scull_qset, int, S_IRUGO);

MODULE_AUTHOR("Alessandro Rubini, Jonathan Corbet");
MODULE_LICENSE("Dual BSD/GPL");

struct scull_dev *scull_devices;    /* allocated in scull_init_module */

#ifdef SCULL_DEBUG /* use proc only if debugging */
/*
 * The proc filesystem: function to read and entry
 */
static void* kmalloc_wrapper(int size, int gfp_mask)
{
	void* ptr = kmalloc(size, gfp_mask);
	printk(KERN_NOTICE "kmalloc: size = %d, ptr = %px\n", size, ptr);
	return ptr;
}

static void kfree_wrapper(void* ptr)
{
	printk(KERN_NOTICE "kfree: ptr = %px\n", ptr);
	kfree(ptr);
}

#define KMALLOC kmalloc_wrapper
#define KFREE kfree_wrapper

int scull_read_procmem(struct seq_file *s, void *v)
{
        int i, j;
        int limit = s->size - 80; /* Don't print more than this */

        for (i = 0; i < scull_nr_devs && s->count <= limit; i++) {
                struct scull_dev *d = &scull_devices[i];
                struct scull_qset *qs = d->data;
                //if (mutex_lock_interruptible(&d->lock))
                //        return -ERESTARTSYS;
                seq_printf(s,"\nDevice %i: qset %i, q %i, sz %li\n",
                             i, d->qset, d->quantum, d->size);
                for (; qs && s->count <= limit; qs = qs->next) { /* scan the list */
                        seq_printf(s, "  item at %p, qset at %p\n",
                                     qs, qs->data);
                        if (qs->data && !qs->next) /* dump only the last item */
                                for (j = 0; j < d->qset; j++) {
                                        if (qs->data[j])
                                                seq_printf(s, "    % 4i: %8p\n",
                                                             j, qs->data[j]);
                                }
                }
                //mutex_unlock(&scull_devices[i].lock);
        }
        return 0;
}

/*
 * Here are our sequence iteration methods.  Our "position" is
 * simply the device number.
 */
static void *scull_seq_start(struct seq_file *s, loff_t *pos)
{
    if (*pos >= scull_nr_devs)
        return NULL;   /* No more to read */
    return scull_devices + *pos;
}

static void *scull_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    (*pos)++;
    if (*pos >= scull_nr_devs)
        return NULL;
    return scull_devices + *pos;
}

static void scull_seq_stop(struct seq_file *s, void *v)
{
    /* Actually, there's nothing to do here */
}

static int scull_seq_show(struct seq_file *s, void *v)
{
    struct scull_dev *dev = (struct scull_dev *) v;
    struct scull_qset *d;
    int i;

    //if (mutex_lock_interruptible(&dev->lock))
    //  return -ERESTARTSYS;
    seq_printf(s, "\nDevice %i: qset %i, q %i, sz %li\n",
            (int) (dev - scull_devices), dev->qset,
            dev->quantum, dev->size);
    for (d = dev->data; d; d = d->next) { /* scan the list */
        seq_printf(s, "  item at %p, qset at %p\n", d, d->data);
        if (d->data && !d->next) /* dump only the last item */
            for (i = 0; i < dev->qset; i++) {
                if (d->data[i])
                    seq_printf(s, "    % 4i: %8p\n",
                            i, d->data[i]);
            }
    }
    //mutex_unlock(&dev->lock);
    return 0;
}
    
/*
 * Tie the sequence operators up.
 */
static struct seq_operations scull_seq_ops = {
    .start = scull_seq_start,
    .next  = scull_seq_next,
    .stop  = scull_seq_stop,
    .show  = scull_seq_show
};

/*
 * Now to implement the /proc files we need only make an open
 * method which sets up the sequence operators.
 */
static int scullmem_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, scull_read_procmem, NULL);
}

static int scullseq_proc_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &scull_seq_ops);
}

/*
 * Create a set of file operations for our proc files.
 */
static struct file_operations scullmem_proc_ops = {
    .owner   = THIS_MODULE,
    .open    = scullmem_proc_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release
};

static struct file_operations scullseq_proc_ops = {
    .owner   = THIS_MODULE,
    .open    = scullseq_proc_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = seq_release
};
    

/*
 * Actually create (and remove) the /proc file(s).
 */

static void scull_create_proc(void)
{
    proc_create_data("scullmem", 0 /* default mode */,
            NULL /* parent dir */, proc_ops_wrapper(&scullmem_proc_ops, scullmem_pops),
            NULL /* client data */);
    proc_create("scullseq", 0, NULL, proc_ops_wrapper(&scullseq_proc_ops, scullseq_pops));
}

static void scull_remove_proc(void)
{
    /* no problem if it was not registered */
    remove_proc_entry("scullmem", NULL /* parent dir */);
    remove_proc_entry("scullseq", NULL);
}

// static unsigned long get_ticks(void)
// {
//     unsigned a, d;
//     asm volatile("rdtsc" : "=a" (a), "=d" (d)); 
//     return ((unsigned long)a) | (((unsigned long )d) << 32);
// }

#else

#define KMALLOC kmalloc
#define KFREE kfree

#endif /* SCULL_DEBUG */

/*
 * Empty out the scull device; must be called with the device
 * semaphore held.
 */
int scull_trim(struct scull_dev *dev)
{
    struct scull_qset *next, *dptr;
    int qset = dev->qset;   /* "dev" is not-null */
    int i;

    for (dptr = dev->data; dptr; dptr = next) { /* all the list items */
        if (dptr->data) {
            for (i = 0; i < qset; i++)
                if (dptr->data[i]) KFREE(dptr->data[i]);
            KFREE(dptr->data);
            cond_resched();
        }
        next = dptr->next;
        KFREE(dptr);
    }
    dev->size = 0;
    dev->quantum = scull_quantum;
    dev->qset = scull_qset;
    dev->data = NULL;
    return 0;
}


/*
 * Open and close
 */

int scull_open(struct inode *inode, struct file *filp)
{
    struct scull_dev *dev; /* device information */

    PDEBUG("scull_open called\n");

    dev = container_of(inode->i_cdev, struct scull_dev, cdev);
    filp->private_data = dev; /* for other methods */

    /* now trim to 0 the length of the device if open was write-only */
    if ( (filp->f_flags & O_ACCMODE) == O_WRONLY) {
        scull_trim(dev); /* ignore errors */
    }
    return 0;          /* success */
}

int scull_release(struct inode *inode, struct file *filp)
{
    return 0;
}
/*
 * Follow the list
 */
struct scull_qset *scull_follow(struct scull_dev *dev, int n)
{
    struct scull_qset *qs = dev->data;

    /* Allocate first qset explicitly if need be */
    if (! qs) {
        qs = dev->data = KMALLOC(sizeof(struct scull_qset), KMALLOC_GFP_MASK);
        if (qs == NULL)
            return NULL;  /* Never mind */
        memset(qs, 0, sizeof(struct scull_qset));
    }

    /* Then follow the list */
    while (n--) {
        if (!qs->next) {
            qs->next = KMALLOC(sizeof(struct scull_qset), KMALLOC_GFP_MASK);
            if (qs->next == NULL)
                return NULL;  /* Never mind */
            memset(qs->next, 0, sizeof(struct scull_qset));
        }
        qs = qs->next;
        continue;
    }
    return qs;
}

/*
 * Data management: read and write
 */

ssize_t scull_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct scull_dev *dev = filp->private_data; 
    struct scull_qset *dptr;    /* the first listitem */
    int quantum = dev->quantum, qset = dev->qset;
    int itemsize = quantum * qset; /* how many bytes in the listitem */
    int item, s_pos, q_pos, rest;
    ssize_t retval = 0;

    if (*f_pos >= dev->size)
        goto out;
    if (*f_pos + count > dev->size)
        count = dev->size - *f_pos;

    /* find listitem, qset index, and offset in the quantum */
    item = (long)*f_pos / itemsize;
    rest = (long)*f_pos % itemsize;
    s_pos = rest / quantum; q_pos = rest % quantum;

    /* follow the list up to the right position (defined elsewhere) */
    dptr = scull_follow(dev, item);

    if (dptr == NULL || !dptr->data || ! dptr->data[s_pos])
        goto out; /* don't fill holes */

    /* read only up to the end of this quantum */
    if (count > quantum - q_pos)
        count = quantum - q_pos;

    if (copy_to_user(buf, dptr->data[s_pos] + q_pos, count)) {
        retval = -EFAULT;
        goto out;
    }
    *f_pos += count;
    retval = count;

out:
    return retval;
}

ssize_t scull_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct scull_dev *dev = filp->private_data;
    struct scull_qset *dptr;
    int quantum = dev->quantum, qset = dev->qset;
    int itemsize = quantum * qset;
    int item, s_pos, q_pos, rest;
    ssize_t retval = -ENOMEM; /* value used in "goto out" statements */

    /* find listitem, qset index and offset in the quantum */
    item = (long)*f_pos / itemsize;
    rest = (long)*f_pos % itemsize;
    s_pos = rest / quantum; q_pos = rest % quantum;

    /* follow the list up to the right position */
    dptr = scull_follow(dev, item);
    if (dptr == NULL)
        goto out;
    if (!dptr->data) {
        dptr->data = KMALLOC(qset * sizeof(char *), KMALLOC_GFP_MASK);
        if (!dptr->data)
            goto out;
        memset(dptr->data, 0, qset * sizeof(char *));
    }
    if (!dptr->data[s_pos]) {
        dptr->data[s_pos] = KMALLOC(quantum, KMALLOC_GFP_MASK);
        if (!dptr->data[s_pos])
            goto out;
    }
    /* write only up to the end of this quantum */
    if (count > quantum - q_pos)
        count = quantum - q_pos;

    if (copy_from_user(dptr->data[s_pos]+q_pos, buf, count)) {
        retval = -EFAULT;
        goto out;
    }
    *f_pos += count;
    retval = count;

    PDEBUG("dptr->data[s_pos]+q_pos = %px[%d]+%d = %px\n", dptr->data, s_pos, q_pos, dptr->data[s_pos]+q_pos);

    /* update the size */
    if (dev->size < *f_pos)
        dev->size = *f_pos;

out:
    return retval;
}


int scull_shift(struct scull_dev *dev, int n_shift)
{
    struct scull_qset *next, *dptr;
    int qset = dev->qset;   // "dev" is not-null 
    int i, j;

    if (n_shift == 0 || qset < 2 || n_shift >= qset) return -1;
    PDEBUG("qset = %d\n", qset);

    //free data first
    for (dptr = dev->data; dptr; dptr = next) { // all the list items
        if (dptr->data) {
            for(i = 0; i < n_shift; ++i) if (dptr->data[i]) KFREE(dptr->data[i]);
            cond_resched();
        }
        next = dptr->next;
    }

    // shift qsets
    for (dptr = dev->data; dptr; dptr = next) { // all the list items
        if (dptr->data) {
            for(i = 0, j = n_shift; j < qset; ++i, ++j) dptr->data[i] = dptr->data[j];
            cond_resched();
        }
        next = dptr->next;
    }

    dev->qset -= n_shift;
    return 0;

}

/*
 * The ioctl() implementation
 */

long scull_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{

    int err = 0, tmp;
    int retval = 0;
    struct scull_dev *dev;

    PDEBUG("scull_ioctl called, dev = %px, pid = %d\n", filp->private_data, current->pid); // added
    
    /*
     * extract the type and number bitfields, and don't decode
     * wrong cmds: return ENOTTY (inappropriate ioctl) before access_ok()
     */
    if (_IOC_TYPE(cmd) != SCULL_IOC_MAGIC) return -ENOTTY;
    if (_IOC_NR(cmd) > SCULL_IOC_MAXNR) return -ENOTTY;

    /*
     * the direction is a bitmask, and VERIFY_WRITE catches R/W
     * transfers. `Type' is user-oriented, while
     * access_ok is kernel-oriented, so the concept of "read" and
     * "write" is reversed
     */
    if (_IOC_DIR(cmd) & _IOC_READ)
        err = !access_ok_wrapper(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
    else if (_IOC_DIR(cmd) & _IOC_WRITE)
        err =  !access_ok_wrapper(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
    if (err) return -EFAULT;

    switch(cmd) {

        case SCULL_IOCRESET:
            scull_quantum = SCULL_QUANTUM;
            scull_qset = SCULL_QSET;
            break;

        case SCULL_IOCSQUANTUM: /* Set: arg points to the value */
            retval = __get_user(scull_quantum, (int __user *)arg);
            break;

        case SCULL_IOCTQUANTUM: /* Tell: arg is the value */
            scull_quantum = arg;
            break;

        case SCULL_IOCGQUANTUM: /* Get: arg is pointer to result */
            retval = __put_user(scull_quantum, (int __user *)arg);
            break;

        case SCULL_IOCQQUANTUM: /* Query: return it (it's positive) */
            return scull_quantum;

        case SCULL_IOCXQUANTUM: /* eXchange: use arg as pointer */
            tmp = scull_quantum;
            retval = __get_user(scull_quantum, (int __user *)arg);
            if (retval == 0)
            retval = __put_user(tmp, (int __user *)arg);
            break;

        case SCULL_IOCHQUANTUM: /* sHift: like Tell + Query */
            tmp = scull_quantum;
            scull_quantum = arg;
            return tmp;

        case SCULL_IOCSQSET:
            retval = __get_user(scull_qset, (int __user *)arg);
            break;

        case SCULL_IOCTQSET:
            scull_qset = arg;
            break;

        case SCULL_IOCGQSET:
            retval = __put_user(scull_qset, (int __user *)arg);
            break;

        case SCULL_IOCQQSET:
            return scull_qset;

        case SCULL_IOCXQSET:
            tmp = scull_qset;
            retval = __get_user(scull_qset, (int __user *)arg);
            if (retval == 0)
            retval = put_user(tmp, (int __user *)arg);
            break;

        case SCULL_IOCHQSET:
            tmp = scull_qset;
            scull_qset = arg;
            return tmp;

        case SCULL_IOCSHIFT:
            dev = filp->private_data;
            if (scull_shift(dev, arg) != 0)
            return -EINVAL;
            break;

        /*
        * The following two change the buffer size for scullpipe.
        * The scullpipe device uses this same ioctl method, just to
        * write less code. Actually, it's the same driver, isn't it?
        */
        // removed pipe
        // case SCULL_P_IOCTSIZE:
        //     scull_p_buffer = arg;
        //     break;

        // case SCULL_P_IOCQSIZE:
        //     return scull_p_buffer;

#ifdef SCULL_DEBUG
        // testing ioctl
        // case SCULL_TEST_SKB:
        //     dev = filp->private_data;
        //     void* buff = KMALLOC(dev->quantum, KMALLOC_GFP_MASK);
        //     PDEBUG("buff = %px\n", buff);
        //     KFREE(buff);
        //     struct sk_buff* skb = alloc_skb(dev->quantum - 320, GFP_KERNEL); // gfp_mask in unix_stream_sendmsg 0x7000c0
        //     PDEBUG( "skb->data = %px, GFP_KERNEL = 0x%x\n", skb->data, GFP_KERNEL);
        //     kfree_skb(skb);
        //     buff = kvmalloc(dev->quantum, GFP_KERNEL);
        //     PDEBUG( "buff2 = %px\n", buff);
        //     KFREE(buff);
        //     break;
        // case SCULL_TEST_SMT:
        //     retval = *(int*)arg;
        //     break;
#endif

        default:  /* redundant, as cmd was checked against MAXNR */
            return -ENOTTY;
    }
    return retval;

}



/*
 * The "extended" operations -- only seek
 */

loff_t scull_llseek(struct file *filp, loff_t off, int whence)
{
    struct scull_dev *dev = filp->private_data;
    loff_t newpos;

    switch(whence) {
      case 0: /* SEEK_SET */
        newpos = off;
        break;

      case 1: /* SEEK_CUR */
        newpos = filp->f_pos + off;
        break;

      case 2: /* SEEK_END */
        newpos = dev->size + off;
        break;

      default: /* can't happen */
        return -EINVAL;
    }
    if (newpos < 0) return -EINVAL;
    filp->f_pos = newpos;
    return newpos;
}



struct file_operations scull_fops = {
    .owner =    THIS_MODULE,
    .llseek =   scull_llseek,
    .read =     scull_read,
    .write =    scull_write,
    .unlocked_ioctl = scull_ioctl,
    .open =     scull_open,
    .release =  scull_release,
};

/*
 * Finally, the module stuff
 */

/*
 * The cleanup function is used to handle initialization failures as well.
 * Thefore, it must be careful to work correctly even if some of the items
 * have not been initialized
 */
void scull_cleanup_module(void)
{
    int i;
    dev_t devno = MKDEV(scull_major, scull_minor);

    /* Get rid of our char dev entries */
    if (scull_devices) {
        for (i = 0; i < scull_nr_devs; i++) {
            scull_trim(scull_devices + i);
            cdev_del(&scull_devices[i].cdev);
        }
        KFREE(scull_devices);
    }

#ifdef SCULL_DEBUG /* use proc only if debugging */
    scull_remove_proc();
#endif

    /* cleanup_module is never called if registering failed */
    unregister_chrdev_region(devno, scull_nr_devs);

    /* and call the cleanup functions for friend devices */
    // removed pipe and access
    // scull_p_cleanup();
    // scull_access_cleanup();

}


/*
 * Set up the char_dev structure for this device.
 */
static void scull_setup_cdev(struct scull_dev *dev, int index)
{
    int err, devno = MKDEV(scull_major, scull_minor + index);
    
    cdev_init(&dev->cdev, &scull_fops);
    dev->cdev.owner = THIS_MODULE;
    err = cdev_add (&dev->cdev, devno, 1);
    /* Fail gracefully if need be */
    if (err)
        printk(KERN_NOTICE "Error %d adding scull%d", err, index);
}


int scull_init_module(void)
{
    int result, i;
    dev_t dev = 0;

    /*
     * Get a range of minor numbers to work with, asking for a dynamic
     * major unless directed otherwise at load time.
     */
    if (scull_major) {
        dev = MKDEV(scull_major, scull_minor);
        result = register_chrdev_region(dev, scull_nr_devs, "scull");
    } else {
        result = alloc_chrdev_region(&dev, scull_minor, scull_nr_devs,
                "scull");
        scull_major = MAJOR(dev);
    }
    if (result < 0) {
        printk(KERN_WARNING "scull: can't get major %d\n", scull_major);
        return result;
    }

    /* 
     * allocate the devices -- we can't have them static, as the number
     * can be specified at load time
     */
    scull_devices = KMALLOC(scull_nr_devs * sizeof(struct scull_dev), KMALLOC_GFP_MASK);
    if (!scull_devices) {
        result = -ENOMEM;
        goto fail;  /* Make this more graceful */
    }
    memset(scull_devices, 0, scull_nr_devs * sizeof(struct scull_dev));

        /* Initialize each device. */
    for (i = 0; i < scull_nr_devs; i++) {
        scull_devices[i].quantum = scull_quantum;
        scull_devices[i].qset = scull_qset;
        mutex_init(&scull_devices[i].lock);
        scull_setup_cdev(&scull_devices[i], i);
    }

    /* At this point call the init function for any friend device */
    // removed pipe and access
    // dev = MKDEV(scull_major, scull_minor + scull_nr_devs);
    // dev += scull_p_init(dev);
    // dev += scull_access_init(dev);

#ifdef SCULL_DEBUG /* only when debugging */
    scull_create_proc();
#endif

    return 0; /* succeed */

  fail:
    scull_cleanup_module();
    return result;
}

module_init(scull_init_module);
module_exit(scull_cleanup_module);
