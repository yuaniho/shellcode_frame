/*
使用 ld 脚本控制 .payload 段内存布局，并指定入口地址
*/

ENTRY(__payload_start)
/* 指定入口地址 */
SECTIONS {

    .payload BLOCK(__section_alignment__) : {
        __payload_start = .;
        /* 获取当前 .payload 段的起始地址 */
        KEEP(*(.payload.entry))
        /* 强行控制使用 .payload.entry 修饰的函数位于 .payload 段的开头 */
        *(.payload)
        __payload_end = .;
    }

}
INSERT AFTER .text;
/* 将 .payload 段插入 .text 段末尾 */