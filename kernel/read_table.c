#include "read_table.h"

vrt_t *_read_table = NULL;
spinlock_t list_lock;

/**
 * @brief Create a read state for the given process and add it to the maintained linked list.
 * 
 * @param pid pid of the process
 * @return int 0 on success, any other return value represents an error.
 */
int
create_new_read_entry(pid_t pid)
{
    vrt_t *temp = _read_table;

    spin_lock(&list_lock);

    if (!temp) {
        _read_table = (vrt_t *) kzalloc(VRT_SIZE, GFP_KERNEL);

        if (!_read_table) {
            return -ENOMEM;
        }

        _read_table->pid = pid;
        _read_table->offset = 0;
        _read_table->next = NULL;
        spin_unlock(&list_lock);
        return PAMKIT_SUCCESS;
    }

    while (temp->next != NULL) {
        temp = temp->next;
    }

    temp->next = (vrt_t *) kzalloc(VRT_SIZE, GFP_KERNEL);

    if (!temp->next) {
        spin_unlock(&list_lock);
        return -ENOMEM;
    }

    temp->next->pid = pid;
    temp->next->offset = 0;
    temp->next->next = NULL;

    spin_unlock(&list_lock);
    return PAMKIT_SUCCESS;
}


/**
 * @brief Get the read state of a specific process.
 * 
 * @param pid pid of the process whose read state should be retrived
 * @return vrt_t* processes read state, NULL if no read state exists
 */
vrt_t *
get_table_entry_by_pid(pid_t pid)
{
    vrt_t *temp = _read_table;

    spin_lock(&list_lock);

    while (temp) {
        if (temp->pid == pid) {
            spin_unlock(&list_lock);
            return temp;
        }
        temp = temp->next;
    }
    spin_unlock(&list_lock);
    return NULL;
}


/**
 * @brief Remove the read state of the process with the specified pid.
 * 
 * @param pid pid of the process whose read state should be removed.
 * @return int 0 on success, if the process has not opened file -EBADFD is returned
 */
int
remove_table_entry_by_pid(pid_t pid)
{
    vrt_t *temp = _read_table;

    if (temp == NULL) {
        return -EBADFD; //process has not opened the virtual file
    }

    spin_lock(&list_lock);

    if (temp->pid == pid) {
        vrt_t *old = _read_table;
        _read_table = _read_table->next;
        kfree(old);
        spin_unlock(&list_lock);
        return PAMKIT_SUCCESS;
    }

    while (temp->next != NULL) {
        if (temp->next->pid == pid) {
            vrt_t *old = temp->next;
            temp->next = temp->next->next;
            kfree(old);
            spin_unlock(&list_lock);
            return PAMKIT_SUCCESS;
        }
    }
    spin_unlock(&list_lock);
    return -EBADFD; //process has not opened the virtual file.
}


/**
 * @brief Reset the offset of the process's read state to 0.
 * 
 * @param pid pid of the process whose read state should be reset.
 */
void
reset_table_entry_by_pid(pid_t pid)
{
    vrt_t *temp = _read_table;

    spin_lock(&list_lock);

    while (temp) {
        if (temp->pid == pid) {
            temp->offset = 0;
            break;
        }
        temp = temp->next;
    }

    spin_unlock(&list_lock);
}

/**
 * @brief Destroy the maintained list of read states and free the used memory.
 * 
 */
void
destroy_list(void)
{
    vrt_t *temp = _read_table;

    spin_lock(&list_lock);

    while (temp) {
        vrt_t *prev = temp;
        temp = temp->next;
        kfree(prev);
    }

    spin_unlock(&list_lock);
}

void
print_list(void)
{
    vrt_t *temp = _read_table;

    spin_lock(&list_lock);

    while (temp) {
        pr_info("(%lu, %lu) -> ", temp->pid, temp->offset);
        temp = temp->next;
    }

    spin_unlock(&list_lock);
}