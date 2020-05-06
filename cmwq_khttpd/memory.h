#ifndef _MEMORY_H_
#define _MEMORY_H_

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>

#include <linux/slab.h>

/*static void *(*orig_malloc)(size_t) = malloc;
static void *(*orig_realloc)(void *, size_t) = realloc;
static void (*orig_free)(void *) = free;*/

// x 系列 function 的實作
/* TODO: implement custom memory allocator which fits arbitrary precision
 * operations
 */
/*
static inline void *xmalloc(size_t size)
{
    void *p;
    if (!(p = (*orig_malloc)(size))) {
        fprintf(stderr, "Out of memory.\n");
        abort();
    }
    return p;
}

static inline void *xrealloc(void *ptr, size_t size)
{
    void *p;
    if (!(p = (*orig_realloc)(ptr, size)) && size != 0) {
        fprintf(stderr, "Out of memory.\n");
        abort();
    }
    return p;
}

static inline void xfree(void *ptr)
{
    (*orig_free)(ptr);
}*/

// xmalloc
// https://stackoverflow.com/questions/7590254/what-is-the-difference-between-xmalloc-and-malloc
// xmalloc 行為基本上跟 malloc 一模一樣，只是 xmalloc 在失敗的時候，會直接停止程式執行
// 而原本的 malloc 則是回傳錯誤碼
// 其他 x 系列的 function 應該都差不多功能
// 原本還在想，為什麼這邊需要用到這麼多的 define
// 現在用起來才知道，程式的擴充性因此高了一層樓。例如我現在突然不想要使用 xmalloc ，想要使用其他的 allocator
// 這時候我只要在這邊改動一行，就通通解決了
#define MALLOC(n) kmalloc(n, GFP_KERNEL)
//#define MALLOC(n) malloc(n)
#define REALLOC(p, n) krealloc(p, n, GFP_KERNEL)
#define FREE(p) kfree(p)

#endif /* !_MEMORY_H_ */



