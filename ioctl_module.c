/*
 *  ioctl test module -- Joe Grand
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h> /* error codes */
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/tty.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/sched.h>
MODULE_LICENSE("GPL");

/* attribute structure, copied to user space */
struct keyboard_char_t {
  char character;
};

/*Cookie for requesting and removing that interrupt */
struct keyboard_cookie_t {
	char * contents;
};
/* structure that holds most recently retrieved character, and some state info*/
struct keyboard_buffer_t {
	char character;
	int shift;
	int ready;
};

static struct keyboard_buffer_t keyboard_buffer;
static struct keyboard_char_t key_input;


static struct keyboard_cookie_t keyboard_cookie = {"imacookie"};
//initialize keyboard wq

wait_queue_head_t keyboard_wq;


#define IOCTL_KEYBOARD _IOR(0, 6, struct keyboard_char_t)

static int pseudo_device_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg);



static struct file_operations pseudo_dev_proc_operations;

static struct proc_dir_entry *proc_entry;

static inline unsigned char inb( unsigned short usPort ) {

    unsigned char uch;
    
    asm volatile( "inb %1,%0" : "=a" (uch) : "Nd" (usPort) );
    return uch;
}

static inline void outb( unsigned char uch, unsigned short usPort ) {

    asm volatile( "outb %0,%1" : : "a" (uch), "Nd" (usPort) );
}


irqreturn_t keyboard_handler(int irq, void *dev_id) {
   char c;
   static char scancode[128] = "0\e1234567890-=\177\tqwertyuiop[]\n\0asdfghjkl;'`\0\\zxcvbnm,./\0*\0 \0\0\0\0\0\0\0\0\0\0\0\0\000789-456+1230.\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"; 
   //****TODO****
   //add key press functionality 
   if ( (c = inb(0x60)) & 0x80) { // a key has been released
		c &= 0x7f; //get the key released
		if( c == 0x2a || c == 0x36) { //Clear shift if we release the shift key
			keyboard_buffer.shift = 0;
		}
      return IRQ_HANDLED;
   }
   
   
   if ( c == 0x2a || c == 0x36) { //detect shift keys
      keyboard_buffer.shift = 1;
      return IRQ_HANDLED;
   }
   
   keyboard_buffer.character = scancode[(int)c];
   
   if( c == 0x0e) {//backspace
      keyboard_buffer.character = 0x08;  
   }else if ( c == 0x1c) { //Enter (shift screws it up)
      if( keyboard_buffer.character >= 0x61 || keyboard_buffer.character <= 0x7D) {
		keyboard_buffer.character -= 0x20;
	  }
   }
   
   keyboard_buffer.ready = 1;

   //wake up the task on the keyboard wait queue
   wake_up_interruptible(&keyboard_wq);
   return IRQ_HANDLED;
}

static int __init initialization_routine(void) {
  int ret;
  unsigned int irq;
  printk("<1> Loading module\n");
  //Need to request an IRQ for the keyboard
  //Get IRQ1
  irq = 1;
  ret = request_irq(irq, keyboard_handler, IRQF_SHARED, "joe", &keyboard_cookie); 
  if (ret < 0){
	  printk(KERN_ALERT "%s: request failed with %d\n", __func__, ret);
	}else if (ret >= 0) {
		printk(KERN_INFO "request successful");
	}
  pseudo_dev_proc_operations.ioctl = pseudo_device_ioctl;
 
  /* Start create proc entry */
  proc_entry = create_proc_entry("ioctl_keyboard_test", 0444, NULL);
  
  if(!proc_entry)
  {
    printk("<1> Error creating /proc entry.\n");
    return 1;
  }

  proc_entry->proc_fops = &pseudo_dev_proc_operations;
  init_waitqueue_head (&keyboard_wq);
  return 0;
}

static void __exit cleanup_routine(void) {
  //Release IRQ1
  //Need to release the IRQ1 for our keyboard driver
  // CAREFUL, need the IRQ to remian active for the Host OS or
  //we lose control of the keyboard
  //assume the irq to be freed is associated with a keyboard_module_cookie
  free_irq(1, &keyboard_cookie);
  remove_proc_entry("ioctl_keyboard_test", NULL);
  printk("<1> Dumping module\n");
  return;
}

/* 'printk' version that prints to active tty. */
void my_printk(char *string)
{
  struct tty_struct *my_tty;

  my_tty = current->signal->tty;

  if (my_tty != NULL) {
    (*my_tty->driver->ops->write)(my_tty, string, strlen(string));
    (*my_tty->driver->ops->write)(my_tty, "\015\012", 2);
  }
} 




/***
 * ioctl() entry point...
 */
static int pseudo_device_ioctl(struct inode *inode, struct file *file,
				unsigned int cmd, unsigned long arg)
{
  
  
  switch (cmd){

  case IOCTL_KEYBOARD:{
    
    //Need to wait for an interrupt "event" to trigger the keyboard ISR.
    //This will wake the thread in the kernel from the keyboard_wq wait queue
    //assuming the keyboard buffer is ready.
    //Specifically, we BLOCK here until the keyboard ISR has woken us up with
    //data entered via the keyboard.
    int copied;
    
    key_input.character = keyboard_buffer.character;
    keyboard_buffer.ready = 0;
    interruptible_sleep_on(&keyboard_wq);
    copied = copy_to_user((struct keyboard_char_t *)arg, &key_input, sizeof(struct keyboard_char_t));
    printk("<1> icotl call to the keyboard driver (%c), but we couldn't copy %u bytes!\n",
			key_input.character, copied);
    break;
	}
    
       
  default:
    return -EINVAL;
    break;
  }
  
  return 0;
}


module_init(initialization_routine); 
module_exit(cleanup_routine); 