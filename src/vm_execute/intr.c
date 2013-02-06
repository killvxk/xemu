#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

#include "execute.h"
#include "gdt.h"
#include "idt.h"
#include "memory.h"
#include "system_state.h"


extern pid_t vm_pid;

static int previous_interrupt = -1;


extern void unhandled_segfault(pid_t pid, siginfo_t *siginfo, struct user_regs_struct *regs);


bool execute_interrupt(struct user_regs_struct *regs, int vector, uint32_t errcode, bool ext)
{
    if ((previous_interrupt >= 0) && (previous_interrupt < 20))
    {
        if (previous_interrupt == 8) // #DF
        {
            fprintf(stderr, "Triple fault, exiting.\n");

            siginfo_t siginfo;
            ptrace(PTRACE_GETSIGINFO, vm_pid, NULL, &siginfo);

            unhandled_segfault(vm_pid, &siginfo, regs);

            return false;
        }

        vector = 8;
    }


    struct xdt_gate_desc *gate = (struct xdt_gate_desc *)adr_g2h(idtr.base) + vector;

    if ((uintptr_t)gate - (uintptr_t)adr_g2h(idtr.base) >= idtr.limit)
    {
        fprintf(stderr, "Interrupt out of bounds (v=%x)\n", vector);
        previous_interrupt = vector;
        return execute_interrupt(regs, 13, (vector << 3) | 2 | ext, false); // #GP
    }


    if (!(gate->type & (1 << 7)))
    {
        fprintf(stderr, "Interrupt gate not present (v=%x)\n", vector);
        previous_interrupt = vector;
        return execute_interrupt(regs, 13, (vector << 3) | 2 | ext, false);
    }

    if (((gate->type & 0x1f) != GATE_INTR) && ((gate->type & 0x1f) != GATE_TRAP))
    {
        fprintf(stderr, "Unknown IDT descriptor type 0x%02x.\n", gate->type & 0x1f);
        previous_interrupt = vector;
        return execute_interrupt(regs, 13, (vector << 3) | 2 | ext, false);
    }


    // FIXME: Limit check
    uint32_t *stack = (uint32_t *)((uintptr_t)adr_g2h(regs->rsp) + gdt_desc_cache[SS].base);

    if (gdt_desc_cache[CS].privilege > (gate->selector & 3))
    {
        if ((tr & ~7) >= gdtr.limit)
        {
            previous_interrupt = vector;
            return execute_interrupt(regs, 10, tr, false);
        }

        struct gdt_desc *tss_desc = adr_g2h(gdtr.base + (tr & ~7));
        uintptr_t tss_base = tss_desc->base_lo | (tss_desc->base_mi << 16) | ((uint64_t)tss_desc->base_hi << 24);

        // FIXME: TSS limit check (and general check whether this is a TSS at all)

        uint16_t old_ss = seg_h2g(regs->ss);

        uint16_t new_ss = *(uint16_t *)((uintptr_t)adr_g2h(tss_base) + 8 + (gate->selector & 3) * 8);

        regs->ss = load_seg_reg(SS, new_ss);
        stack    = (uint32_t *)((uintptr_t)adr_g2h(*(uint32_t *)((uintptr_t)adr_g2h(tss_base) + 4 + (gate->selector & 3) * 8)) + gdt_desc_cache[SS].base);

        *(--stack) = old_ss;
        *(--stack) = regs->rsp;


        // WARNING: DON'T TRY THIS AT HOME (also FIXME)
        if (!(regs->ds & (1 << 2)))
            regs->ds = load_seg_reg(DS, new_ss);
        if (!(regs->es & (1 << 2)))
            regs->es = load_seg_reg(ES, new_ss);
    }

    *(--stack) = regs->eflags;
    *(--stack) = seg_h2g(regs->cs);
    *(--stack) = regs->rip;


    if ((vector == 8) || ((vector >= 10) && (vector <= 14)) || (vector == 17))
        *(--stack) = errcode;


    regs->rsp = (uintptr_t)adr_h2g(stack) - gdt_desc_cache[SS].base;

    regs->cs  = load_seg_reg(CS, gate->selector);
    regs->rip = gate->offset_lo | (gate->offset_hi << 16);


    if ((gate->type & 0x1f) == GATE_INTR)
        int_flag = false;


    previous_interrupt = -1;

    return true;
}
