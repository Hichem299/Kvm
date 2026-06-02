// SPDX-License-Identifier: GPL-2.0-only
/*
 * arch/arm64/kvm/arm.c - Simplified KVM Host support stub for Samsung A05s
 *
 * Based on upstream Linux KVM/ARM64 host interface.
 * Stripped pKVM / Google hypervisor dependencies.
 * Supports: KVM Host mode, MMIO, IRQ chip, VCPU run loop.
 */

#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/percpu.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <linux/kvm.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/highmem.h>
#include <linux/interrupt.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/clocksource.h>
#include <linux/cpuhotplug.h>
#include <linux/reboot.h>

#include <asm/kvm_asm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_emulate.h>
#include <asm/sections.h>
#include <asm/sysreg.h>
#include <asm/cpufeature.h>
#include <asm/virt.h>

#ifdef CONFIG_KVM_ARM_HOST

/* --------------------------------------------------------------------------
 * Global state
 * -------------------------------------------------------------------------- */

static DEFINE_PER_CPU(unsigned char, kvm_arm_hardware_enabled);
DEFINE_STATIC_KEY_FALSE(userspace_irqchip_in_use);

/* --------------------------------------------------------------------------
 * Basic KVM capability checks
 * -------------------------------------------------------------------------- */

int kvm_arch_hardware_setup(void *opaque)
{
	return 0;
}

int kvm_arch_check_processor_compat(void *opaque)
{
	return 0;
}

int kvm_arch_hardware_enable(void)
{
	__this_cpu_write(kvm_arm_hardware_enabled, 1);
	return 0;
}

void kvm_arch_hardware_disable(void)
{
	__this_cpu_write(kvm_arm_hardware_enabled, 0);
}

/* --------------------------------------------------------------------------
 * VM creation / destruction
 * -------------------------------------------------------------------------- */

int kvm_arch_init_vm(struct kvm *kvm, unsigned long type)
{
	int ret;

	ret = kvm_init_stage2_mmu(kvm, &kvm->arch.mmu, type);
	if (ret)
		return ret;

	kvm->arch.vmid.vmid_gen = 0;
	kvm->arch.max_vcpus    = KVM_MAX_VCPUS;
	return 0;
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	int i;

	kvm_unshare_hyp(kvm, sizeof(*kvm));

	for (i = 0; i < KVM_MAX_VCPUS; i++) {
		if (kvm->vcpus[i]) {
			kvm_vcpu_destroy(kvm->vcpus[i]);
			kvm->vcpus[i] = NULL;
		}
	}
	atomic_set(&kvm->online_vcpus, 0);
}

int kvm_vm_ioctl_check_extension(struct kvm *kvm, long ext)
{
	switch (ext) {
	case KVM_CAP_IRQCHIP:
	case KVM_CAP_IOEVENTFD:
	case KVM_CAP_DEVICE_CTRL:
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_SYNC_MMU:
	case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
	case KVM_CAP_ONE_REG:
	case KVM_CAP_ARM_PSCI:
	case KVM_CAP_ARM_PSCI_0_2:
	case KVM_CAP_READONLY_MEM:
	case KVM_CAP_MP_STATE:
	case KVM_CAP_IMMEDIATE_EXIT:
	case KVM_CAP_VCPU_EVENTS:
		return 1;
	case KVM_CAP_NR_VCPUS:
		return num_online_cpus();
	case KVM_CAP_MAX_VCPUS:
	case KVM_CAP_MAX_VCPU_ID:
		return KVM_MAX_VCPUS;
	default:
		return 0;
	}
}

/* --------------------------------------------------------------------------
 * VCPU creation / reset / destruction
 * -------------------------------------------------------------------------- */

int kvm_arch_vcpu_precreate(struct kvm *kvm, unsigned int id)
{
	if (irqchip_in_kernel(kvm) && vgic_initialized(kvm))
		return -EBUSY;
	if (id >= kvm->arch.max_vcpus)
		return -EINVAL;
	return 0;
}

int kvm_arch_vcpu_create(struct kvm_vcpu *vcpu)
{
	int err;

	/* VGIC */
	err = kvm_vgic_vcpu_init(vcpu);
	if (err)
		return err;

	/* Timer */
	kvm_timer_vcpu_init(vcpu);

	/* PMU stub */
	vcpu->arch.target = -1;
	bitmap_zero(vcpu->arch.features, KVM_VCPU_MAX_FEATURES);

	return 0;
}

void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	kvm_timer_vcpu_terminate(vcpu);
	kvm_pmu_vcpu_destroy(vcpu);
	kvm_mmu_free_memory_caches(vcpu);
}

int kvm_arch_vcpu_reset(struct kvm_vcpu *vcpu, bool is_reset)
{
	vcpu_reset_hcr(vcpu);
	memset(&vcpu->arch.ctxt, 0, sizeof(vcpu->arch.ctxt));
	return 0;
}

/* --------------------------------------------------------------------------
 * VCPU run
 * -------------------------------------------------------------------------- */

static int kvm_vcpu_first_run_init(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	int ret = 0;

	if (likely(vcpu->arch.has_run_once))
		return 0;

	if (!kvm_arm_vcpu_is_finalized(vcpu))
		return -EPERM;

	vcpu->arch.has_run_once = true;

	if (likely(irqchip_in_kernel(kvm))) {
		ret = kvm_timer_enable(vcpu);
		if (ret)
			return ret;
	}

	return ret;
}

int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu)
{
	struct kvm_run *run = vcpu->run;
	int ret;

	if (run->exit_reason == KVM_EXIT_MMIO) {
		ret = kvm_handle_mmio_return(vcpu);
		if (ret)
			return ret;
	}

	ret = kvm_vcpu_first_run_init(vcpu);
	if (ret)
		return ret;

	if (run->immediate_exit)
		return -EINTR;

	kvm_sigset_activate(vcpu);

	ret = 1;
	run->exit_reason = KVM_EXIT_UNKNOWN;

	while (ret > 0) {
		/*
		 * Check conditions before entering guest.
		 */
		ret = xfer_to_guest_mode_handle_work(vcpu);
		if (!ret)
			ret = 1;

		if (ret > 0)
			ret = kvm_arm_vcpu_enter_exit(vcpu);
	}

	kvm_sigset_deactivate(vcpu);
	return ret;
}

/* --------------------------------------------------------------------------
 * VCPU get/set registers (one-reg interface)
 * -------------------------------------------------------------------------- */

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	return -ENOIOCTLCMD;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	return -ENOIOCTLCMD;
}

static int copy_core_reg_indices(const struct kvm_vcpu *vcpu,
				 u64 __user *uindices)
{
	unsigned int i;
	int n = 0;

	for (i = 0; i < sizeof(struct kvm_regs) / sizeof(__u32); i++) {
		if (uindices) {
			if (put_user(KVM_REG_ARM64 | KVM_REG_SIZE_U64 | i,
				     uindices))
				return -EFAULT;
			uindices++;
		}
		n++;
	}
	return n;
}

unsigned long kvm_arch_vcpu_num_regs(struct kvm_vcpu *vcpu)
{
	return copy_core_reg_indices(vcpu, NULL);
}

int kvm_arch_vcpu_copy_reg_indices(struct kvm_vcpu *vcpu, u64 __user *uindices)
{
	return copy_core_reg_indices(vcpu, uindices);
}

int kvm_arm_get_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	/* Core registers handled here; others delegated */
	if ((reg->id & KVM_REG_ARM_COPROC_MASK) == KVM_REG_ARM_CORE)
		return kvm_arm_copy_reg_to_user(vcpu, reg);

	return kvm_arm_sys_reg_get_reg(vcpu, reg);
}

int kvm_arm_set_reg(struct kvm_vcpu *vcpu, const struct kvm_one_reg *reg)
{
	if ((reg->id & KVM_REG_ARM_COPROC_MASK) == KVM_REG_ARM_CORE)
		return kvm_arm_copy_reg_from_user(vcpu, reg);

	return kvm_arm_sys_reg_set_reg(vcpu, reg);
}

/* --------------------------------------------------------------------------
 * VCPU MP state
 * -------------------------------------------------------------------------- */

int kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	if (vcpu->arch.power_off)
		mp_state->mp_state = KVM_MP_STATE_STOPPED;
	else
		mp_state->mp_state = KVM_MP_STATE_RUNNABLE;
	return 0;
}

int kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	switch (mp_state->mp_state) {
	case KVM_MP_STATE_RUNNABLE:
		vcpu->arch.power_off = false;
		break;
	case KVM_MP_STATE_STOPPED:
		vcpu->arch.power_off = true;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/* --------------------------------------------------------------------------
 * Guest memory / MMU
 * -------------------------------------------------------------------------- */

int kvm_arch_prepare_memory_region(struct kvm *kvm,
				   const struct kvm_memory_slot *old,
				   struct kvm_memory_slot *new,
				   enum kvm_mr_change change)
{
	return 0;
}

void kvm_arch_commit_memory_region(struct kvm *kvm,
				   struct kvm_memory_slot *old,
				   const struct kvm_memory_slot *new,
				   enum kvm_mr_change change)
{
	/*
	 * Unmap old slot pages from stage-2 on deletion / shrink.
	 */
	if ((change == KVM_MR_DELETE) || (change == KVM_MR_MOVE)) {
		kvm_unmap_stage2_range(kvm, old->base_gfn,
				       old->npages);
	}
}

void kvm_arch_flush_shadow_all(struct kvm *kvm)
{
	kvm_free_stage2_pgd(&kvm->arch.mmu);
}

void kvm_arch_flush_shadow_memslot(struct kvm *kvm,
				   struct kvm_memory_slot *slot)
{
	kvm_unmap_stage2_range(kvm, slot->base_gfn, slot->npages);
}

/* --------------------------------------------------------------------------
 * IRQ / MMIO stubs
 * -------------------------------------------------------------------------- */

int kvm_arch_irq_bypass_add_producer(struct irq_bypass_consumer *cons,
				     struct irq_bypass_producer *prod)
{
	return 0;
}

void kvm_arch_irq_bypass_del_producer(struct irq_bypass_consumer *cons,
				      struct irq_bypass_producer *prod)
{
}

void kvm_arch_irq_bypass_stop(struct irq_bypass_consumer *cons)
{
}

void kvm_arch_irq_bypass_start(struct irq_bypass_consumer *cons)
{
}

/* --------------------------------------------------------------------------
 * Module init / exit
 * -------------------------------------------------------------------------- */

static int arm_init(void)
{
	int rc = kvm_init(sizeof(struct kvm_vcpu), 0, THIS_MODULE);
	if (rc)
		return rc;
	return 0;
}

module_init(arm_init);
MODULE_AUTHOR("KVM-ARM Host Stub");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Simplified KVM Host for Samsung A05s (no pKVM)");

#endif /* CONFIG_KVM_ARM_HOST */
