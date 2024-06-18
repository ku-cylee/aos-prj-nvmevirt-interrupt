// SPDX-License-Identifier: GPL-2.0-only

#include <linux/pci.h>
#include <linux/irq.h>
#include <linux/version.h>
#include <linux/io.h>

#include <linux/percpu-defs.h>
#include <linux/sched/clock.h>

#include "nvmev.h"
#include "pci.h"

#define MSIX_TABLE_SIZE 128

struct msix_table_entry {
	u32 msg_addr_lo;
	u32 msg_addr_hi;
	u32 msg_data;
	u32 vector_ctrl;
};

static unsigned int event_count[MSIX_TABLE_SIZE] = { 0 };
static struct timer_list coalesce_timer;

static void coalesce_timer_callback(struct timer_list *t);
static void start_coalesce_timer(void);
void init_coalesce_timer(void);

void end_coalesce_timer(void) {
	del_timer_sync(&coalesce_timer);
}

static void __process_msi_irq(int msi_index);
static void __process_msix_irq(int msi_index);
static void __signal_irq(const char *type, unsigned int irq);

void init_coalesce_timer(void) {
	timer_setup(&coalesce_timer, coalesce_timer_callback, 0);

	start_coalesce_timer();
}

void start_coalesce_timer(void) {
	mod_timer(&coalesce_timer, jiffies + usecs_to_jiffies(100 * (nvmev_vdev->intr_time + 1)));
}

static void coalesce_timer_callback(struct timer_list *t) {
	int i;
	unsigned long current_time = jiffies;
	for (i = 0; i < MSIX_TABLE_SIZE; i++) {
		if (event_count[i] > 0) {
			if (nvmev_vdev->pdev->msix_enabled) {
				__process_msix_irq(i);
			} else if (nvmev_vdev->pdev->msi_enabled) {
				__process_msi_irq(i);
			} else {
				nvmev_vdev->pcihdr->sts.is = 1;
				__signal_irq("int", nvmev_vdev->pdev->irq);
			}
			event_count[i] = 0;
		}
	}

	start_coalesce_timer();
}

#ifdef CONFIG_NVMEV_FAST_X86_IRQ_HANDLING
static int apicid_to_cpuid[256];

static void __init_apicid_to_cpuid(void)
{
	int i;
	for_each_possible_cpu(i) {
		apicid_to_cpuid[per_cpu(x86_cpu_to_apicid, i)] = i;
	}
}

static void __signal_irq(const char *type, unsigned int irq)
{
	struct irq_data *irqd = irq_get_irq_data(irq);
	struct irq_cfg *irqc = irqd_cfg(irqd);

	unsigned int target = irqc->dest_apicid;
	unsigned int target_cpu = apicid_to_cpuid[target];

	NVMEV_DEBUG_VERBOSE("irq: %s %d, vector %d, apic %d, cpu %d\n", type, irq, irqc->vector, target, target_cpu);
	apic->send_IPI(target_cpu, irqc->vector);

	return;
}
#else
static void __signal_irq(const char *type, unsigned int irq)
{
	struct irq_data *data = irq_get_irq_data(irq);
	struct irq_chip *chip = irq_data_get_irq_chip(data);
	// NVMEV_INFO("Signal irq: %u mask %u, irq %u, hwirq %lx ", irq, data->mask, data->irq, data->hwirq);

	NVMEV_DEBUG_VERBOSE("irq: %s %d, vector %d\n", type, irq, irqd_cfg(data)->vector);
	BUG_ON(!chip->irq_retrigger);
	chip->irq_retrigger(data);

	return;
}
#endif

static bool is_msix_masked(int msi_index) {
	void __iomem *msix_table = nvmev_vdev->msix_table;

	size_t entry_size = sizeof(struct msix_table_entry);
	void __iomem *entry_ptr = msix_table + msi_index * entry_size;

	u32 msi_addr_lo = ioread32(entry_ptr + offsetof(struct msix_table_entry, msg_addr_lo));
	u32 msi_addr_hi = ioread32(entry_ptr + offsetof(struct msix_table_entry, msg_addr_hi));
	u64 msi_addr = (u64)msi_addr_hi << 32 | msi_addr_lo;

	u32 msi_data = ioread32(entry_ptr + offsetof(struct msix_table_entry, msg_data));
	u32 vector_ctrl = ioread32(entry_ptr + offsetof(struct msix_table_entry, vector_ctrl));
	
	if (vector_ctrl != 0)
		NVMEV_INFO("%llx %u %u\n", msi_addr, msi_data, vector_ctrl);
	return true;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
static void __process_msix_irq(int msi_index)
{
	is_msix_masked(msi_index);

	unsigned int virq = msi_get_virq(&nvmev_vdev->pdev->dev, msi_index);

	BUG_ON(virq == 0);
	__signal_irq("msi", virq);
}
#else
static void __process_msix_irq(int msi_index)
{
	struct msi_desc *msi_desc, *tmp;

	for_each_msi_entry_safe(msi_desc, tmp, (&nvmev_vdev->pdev->dev)) {
		if (msi_desc->msi_attrib.entry_nr == msi_index) {
			__signal_irq("msi", msi_desc->irq);
			return;
		}
	}
	NVMEV_INFO("Failed to send IPI\n");
	BUG_ON(!msi_desc);
}
#endif

static bool is_msi_masked(int msi_index) {
	u32 mask = nvmev_vdev->msicap->mmask.mask;

	if (mask & (1 << msi_index))
		NVMEV_INFO("Hello");
	
	return true;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
static void __process_msi_irq(int msi_index)
{
	is_msi_masked(msi_index);

	unsigned int virq = msi_get_virq(&nvmev_vdev->pdev->dev, msi_index);

	BUG_ON(virq == 0);
	__signal_irq("msi", virq);
}
#else
static void __process_msi_irq(int msi_index)
{
	struct msi_desc *msi_desc, *tmp;

	for_each_msi_entry_safe(msi_desc, tmp, (&nvmev_vdev->pdev->dev)) {
		if (msi_desc->msi_attrib.entry_nr == msi_index) {
			__signal_irq("msi", msi_desc->irq);
			return;
		}
	}
	NVMEV_INFO("Failed to send IPI\n");
	BUG_ON(!msi_desc);
}
#endif

void nvmev_signal_irq(int msi_index, bool is_admin)
{
	// Adming Interrupt should not be coalesced
	if (!is_admin) {
		event_count[msi_index]++;
		
		if (event_count[msi_index] >= nvmev_vdev->intr_thr) {
			event_count[msi_index] = 0;
		}
		else {
			return;
		}
	}

	if (nvmev_vdev->pdev->msix_enabled) {
		__process_msix_irq(msi_index);
		// NVMEV_INFO("%d\n", msi_index);
	} else if (nvmev_vdev->pdev->msi_enabled) {
		__process_msi_irq(msi_index);
		// NVMEV_INFO("%d\n", msi_index);
	} else {
		nvmev_vdev->pcihdr->sts.is = 1;
		__signal_irq("int", nvmev_vdev->pdev->irq);
	}
}

/*
 * The host device driver can change multiple locations in the BAR.
 * In a real device, these changes are processed one after the other,
 * preserving their requesting order. However, in NVMeVirt, the changes
 * can be DETECTED with the dispatcher, obsecuring the order between
 * changes that are made between the checking loop. Thus, we have to
 * process the changes strategically, in an order that are supposed
 * to be...
 *
 * Also, memory barrier is not necessary here since BAR-related
 * operations are only processed by the dispatcher.
 *
 * Returns true if an event is processed.
 */
bool nvmev_proc_bars(void)
{
	volatile struct __nvme_bar *old_bar = nvmev_vdev->old_bar;
	volatile struct nvme_ctrl_regs *bar = nvmev_vdev->bar;
	struct nvmev_admin_queue *queue = nvmev_vdev->admin_q;
	unsigned int num_pages, i;

#if 0 /* Read-only register */
	if (old_bar->cap != bar->u_cap) {
		memcpy(&old_bar->cap, &bar->cap, sizeof(old_bar->cap));
	}
	if (old_bar->vs != bar->u_vs) {
		memcpy(&old_bar->vs, &bar->vs, sizeof(old_bar->vs));
	}
	if (old_bar->cmbloc != bar->u_cmbloc) {
		memcpy(&old_bar->cmbloc, &bar->cmbloc, sizeof(old_bar->cmbloc));
	}
	if (old_bar->cmbsz != bar->u_cmbsz) {
		memcpy(&old_bar->cmbsz, &bar->cmbsz, sizeof(old_bar->cmbsz));
	}
	if (old_bar->rsvd1 != bar->rsvd1) {
		memcpy(&old_bar->rsvd1, &bar->rsvd1, sizeof(old_bar->rsvd1));
	}
	if (old_bar->csts != bar->u_csts) {
		memcpy(&old_bar->csts, &bar->csts, sizeof(old_bar->csts));
	}
#endif
#if 0 /* Unused registers */
	if (old_bar->intms != bar->intms) {
		memcpy(&old_bar->intms, &bar->intms, sizeof(old_bar->intms));
	}
	if (old_bar->intmc != bar->intmc) {
		memcpy(&old_bar->intmc, &bar->intmc, sizeof(old_bar->intmc));
	}
	if (old_bar->nssr != bar->nssr) {
		memcpy(&old_bar->nssr, &bar->nssr, sizeof(old_bar->nssr));
	}
#endif
	if (old_bar->aqa != bar->u_aqa) {
		// Initalize admin queue
		NVMEV_DEBUG("%s: aqa 0x%x -> 0x%x\n", __func__, old_bar->aqa, bar->u_aqa);
		old_bar->aqa = bar->u_aqa;

		if (!queue) {
			queue = kzalloc(sizeof(struct nvmev_admin_queue), GFP_KERNEL);
			BUG_ON(queue == NULL);
			WRITE_ONCE(nvmev_vdev->admin_q, queue);
		} else {
			queue = nvmev_vdev->admin_q;
		}

		queue->cq_head = 0;
		queue->phase = 1;
		queue->sq_depth = bar->aqa.asqs + 1; /* asqs and acqs are 0-based */
		queue->cq_depth = bar->aqa.acqs + 1;

		nvmev_vdev->dbs[0] = nvmev_vdev->old_dbs[0] = 0;
		nvmev_vdev->dbs[1] = nvmev_vdev->old_dbs[1] = 0;

		goto out;
	}
	if (old_bar->asq != bar->u_asq) {
		if (queue == NULL) {
			/*
			 * asq/acq can't be updated later than aqa, but in an unlikely case, this
			 * can be triggered before an aqa update due to memory re-ordering and lack
			 * of barriers.
			 *
			 * If that's the case, simply run the loop again after a full barrier so
			 * that the aqa code (initializing the admin queue) can run prior to this.
			 */
			NVMEV_INFO("asq triggered before aqa, retrying\n");
			goto out;
		}

		NVMEV_DEBUG("%s: asq 0x%llx -> 0x%llx\n", __func__, old_bar->asq, bar->u_asq);
		old_bar->asq = bar->u_asq;

		if (queue->nvme_sq) {
			kfree(queue->nvme_sq);
			queue->nvme_sq = NULL;
		}

		queue->sq_depth = bar->aqa.asqs + 1; /* asqs and acqs are 0-based */

		num_pages = DIV_ROUND_UP(queue->sq_depth * sizeof(struct nvme_command), PAGE_SIZE);
		queue->nvme_sq = kcalloc(num_pages, sizeof(struct nvme_command *), GFP_KERNEL);
		BUG_ON(!queue->nvme_sq && "Error on setup admin submission queue");

		for (i = 0; i < num_pages; i++) {
			queue->nvme_sq[i] =
				page_address(pfn_to_page(nvmev_vdev->bar->u_asq >> PAGE_SHIFT) + i);
		}

		nvmev_vdev->dbs[0] = nvmev_vdev->old_dbs[0] = 0;

		goto out;
	}
	if (old_bar->acq != bar->u_acq) {
		if (queue == NULL) {
			// See comment above
			NVMEV_INFO("acq triggered before aqa, retrying\n");
			goto out;
		}

		NVMEV_DEBUG("%s: acq 0x%llx -> 0x%llx\n", __func__, old_bar->acq, bar->u_acq);
		old_bar->acq = bar->u_acq;

		if (queue->nvme_cq) {
			kfree(queue->nvme_cq);
			queue->nvme_cq = NULL;
		}

		queue->cq_depth = bar->aqa.acqs + 1; /* asqs and acqs are 0-based */

		num_pages =
			DIV_ROUND_UP(queue->cq_depth * sizeof(struct nvme_completion), PAGE_SIZE);
		queue->nvme_cq = kcalloc(num_pages, sizeof(struct nvme_completion *), GFP_KERNEL);
		BUG_ON(!queue->nvme_cq && "Error on setup admin completion queue");
		queue->cq_head = 0;

		for (i = 0; i < num_pages; i++) {
			queue->nvme_cq[i] =
				page_address(pfn_to_page(nvmev_vdev->bar->u_acq >> PAGE_SHIFT) + i);
		}

		nvmev_vdev->dbs[1] = nvmev_vdev->old_dbs[1] = 0;

		goto out;
	}
	if (old_bar->cc != bar->u_cc) {
		NVMEV_DEBUG("%s: cc 0x%x:%x -> 0x%x:%x\n", __func__, old_bar->cc, old_bar->csts, bar->u_cc,
			    bar->u_csts);
		/* Enable */
		if (bar->cc.en == 1) {
			if (nvmev_vdev->admin_q) {
				bar->csts.rdy = 1;
			} else {
				WARN_ON("Enable device without init admin q");
			}
		} else if (bar->cc.en == 0) {
			bar->csts.rdy = 0;
		}

		/* Shutdown */
		if (bar->cc.shn == 1) {
			bar->csts.shst = 2;

			nvmev_vdev->dbs[0] = nvmev_vdev->old_dbs[0] = 0;
			nvmev_vdev->dbs[1] = nvmev_vdev->old_dbs[1] = 0;
			nvmev_vdev->admin_q->cq_head = 0;
		}

		old_bar->cc = bar->u_cc;

		goto out;
	}

	return false;

out:
	smp_mb();
	return true;
}

static int nvmev_pci_read(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 *val)
{
	if (devfn != 0)
		return 1;

	memcpy(val, nvmev_vdev->virtDev + where, size);

	NVMEV_DEBUG_VERBOSE("[R] 0x%x, size: %d, val: 0x%x\n", where, size, *val);

	return 0;
};

static int nvmev_pci_write(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 _val)
{
	u32 mask = ~(0U);
	u32 val = 0x00;
	int target = where;

	WARN_ON(size > sizeof(_val));

	memcpy(&val, nvmev_vdev->virtDev + where, size);

	if (where < OFFS_PCI_PM_CAP) {
		// PCI_HDR
		if (target == PCI_COMMAND) {
			mask = PCI_COMMAND_INTX_DISABLE;
			if ((val ^ _val) & PCI_COMMAND_INTX_DISABLE) {
				nvmev_vdev->intx_disabled = !!(_val & PCI_COMMAND_INTX_DISABLE);
				if (!nvmev_vdev->intx_disabled) {
					nvmev_vdev->pcihdr->sts.is = 0;
				}
				NVMEV_INFO("Polling! %d", nvmev_vdev->intx_disabled);
			}
		} else if (target == PCI_STATUS) {
			mask = 0xF200;
		} else if (target == PCI_BIST) {
			mask = PCI_BIST_START;
		} else if (target == PCI_BASE_ADDRESS_0) {
			mask = 0xFFFFC000;
		} else if (target == PCI_INTERRUPT_LINE) {
			mask = 0xFF;
		} else {
			mask = 0x0;
		}
	} else if (where < OFFS_PCI_MSI_CAP) { // AOS: Add msi_cap
		// PCI_PM_CAP
	} else if (where < OFFS_PCI_MSIX_CAP) {
		// PCI_MSI_CAP
		target -= OFFS_PCI_MSI_CAP;
		if (target == PCI_MSI_FLAGS) {
			mask = PCI_MSI_FLAGS_ENABLE | PCI_MSI_FLAGS_QSIZE | PCI_MSI_FLAGS_QMASK;
			if ((nvmev_vdev->pdev) && ((val ^ _val) & PCI_MSI_FLAGS_ENABLE)) {
				nvmev_vdev->pdev->msi_enabled = !!(_val & PCI_MSI_FLAGS_ENABLE);
			}
		} else if (target == PCI_MSI_ADDRESS_LO) {
			mask = ~(0U);
		} else if (target == PCI_MSI_ADDRESS_HI) {
			mask = ~(0U);
		} else if (target == PCI_MSI_DATA_64) { // C64 enabled in default configuration
			mask = ~(0U);
		} else if (target == PCI_MSI_MASK_64) {
			NVMEV_INFO("Masked");
			NVMEV_INFO("new: 0x%x\n", (val & (~mask)) | (_val & mask));
			mask = ~(0U);
		} else if (target == PCI_MSI_PENDING_64) {
			NVMEV_INFO("Pend Set");
			mask = ~(0U);
		} else {
			mask = 0x0;
		}
		// AOS: Adding Multi MSI and Masking?
	} else if (where < OFFS_PCIE_CAP) {
		// PCI_MSIX_CAP
		target -= OFFS_PCI_MSIX_CAP;
		if (target == PCI_MSIX_FLAGS) {
			mask = PCI_MSIX_FLAGS_MASKALL | /* 0x4000 */
			       PCI_MSIX_FLAGS_ENABLE; /* 0x8000 */

			if ((nvmev_vdev->pdev) && ((val ^ _val) & PCI_MSIX_FLAGS_ENABLE)) {
				nvmev_vdev->pdev->msix_enabled = !!(_val & PCI_MSIX_FLAGS_ENABLE);
			}
		} else {
			mask = 0x0;
		}
	} else if (where < OFFS_PCI_EXT_CAP) {
		// PCIE_CAP
	} else {
		// PCI_EXT_CAP
	}
	NVMEV_DEBUG_VERBOSE("[W] 0x%x, mask: 0x%x, val: 0x%x -> 0x%x, size: %d, new: 0x%x\n", where, mask,
		    val, _val, size, (val & (~mask)) | (_val & mask));

	val = (val & (~mask)) | (_val & mask);
	memcpy(nvmev_vdev->virtDev + where, &val, size);

	return 0;
};

static struct pci_ops nvmev_pci_ops = {
	.read = nvmev_pci_read,
	.write = nvmev_pci_write,
};

static struct pci_sysdata nvmev_pci_sysdata = {
	.domain = NVMEV_PCI_DOMAIN_NUM,
	.node = 0,
};


static void __dump_pci_dev(struct pci_dev *dev)
{
	/*
	NVMEV_DEBUG("bus: %p, subordinate: %p\n", dev->bus, dev->subordinate);
	NVMEV_DEBUG("vendor: %x, device: %x\n", dev->vendor, dev->device);
	NVMEV_DEBUG("s_vendor: %x, s_device: %x\n", dev->subsystem_vendor, dev->subsystem_device);
	NVMEV_DEBUG("devfn: %u, class: %x\n", dev->devfn, dev->class);
	NVMEV_DEBUG("sysdata: %p, slot: %p\n", dev->sysdata, dev->slot);
	NVMEV_DEBUG("pin: %d, irq: %u\n", dev->pin, dev->irq);
	NVMEV_DEBUG("msi: %d, msi-x:%d\n", dev->msi_enabled, dev->msix_enabled);
	NVMEV_DEBUG("resource[0]: %llx\n", pci_resource_start(dev, 0));
	*/
}

static void __init_nvme_ctrl_regs(struct pci_dev *dev)
{
	struct nvme_ctrl_regs *bar = memremap(pci_resource_start(dev, 0), PAGE_SIZE * 2, MEMREMAP_WT);
	BUG_ON(!bar);

	nvmev_vdev->bar = bar;
	memset(bar, 0x0, PAGE_SIZE * 2);

	nvmev_vdev->dbs = ((void *)bar) + PAGE_SIZE;

	*bar = (struct nvme_ctrl_regs) {
		.cap = {
			.to = 1,
			.mpsmin = 0,
			.mqes = 1024 - 1, // 0-based value
#if (SUPPORTED_SSD_TYPE(ZNS))
			.css = CAP_CSS_BIT_SPECIFIC,
#endif
		},
		.vs = {
			.mjr = 1,
			.mnr = 0,
		},
	};
}

static struct pci_bus *__create_pci_bus(void)
{
	struct pci_bus *bus = NULL;
	struct pci_dev *dev;

	nvmev_pci_sysdata.node = cpu_to_node(nvmev_vdev->config.cpu_nr_dispatcher);

	bus = pci_scan_bus(NVMEV_PCI_BUS_NUM, &nvmev_pci_ops, &nvmev_pci_sysdata);

	if (!bus) {
		NVMEV_ERROR("Unable to create PCI bus\n");
		return NULL;
	}

	/* XXX Only support a singe NVMeVirt instance in the system for now */
	list_for_each_entry(dev, &bus->devices, bus_list) {
		struct resource *res = &dev->resource[0];
		res->parent = &iomem_resource;

		nvmev_vdev->pdev = dev;
		dev->irq = nvmev_vdev->pcihdr->intr.iline;
		__dump_pci_dev(dev);

		__init_nvme_ctrl_regs(dev);

		nvmev_vdev->old_dbs = kzalloc(PAGE_SIZE, GFP_KERNEL);
		BUG_ON(!nvmev_vdev->old_dbs && "allocating old DBs memory");
		memcpy(nvmev_vdev->old_dbs, nvmev_vdev->dbs, sizeof(*nvmev_vdev->old_dbs));

		nvmev_vdev->old_bar = kzalloc(PAGE_SIZE, GFP_KERNEL);
		BUG_ON(!nvmev_vdev->old_bar && "allocating old BAR memory");
		memcpy(nvmev_vdev->old_bar, nvmev_vdev->bar, sizeof(*nvmev_vdev->old_bar));

		nvmev_vdev->msix_table =
			memremap(pci_resource_start(nvmev_vdev->pdev, 0) + PAGE_SIZE * 2,
				 NR_MAX_IO_QUEUE * PCI_MSIX_ENTRY_SIZE, MEMREMAP_WT);
		memset(nvmev_vdev->msix_table, 0x00, NR_MAX_IO_QUEUE * PCI_MSIX_ENTRY_SIZE);
	}

	NVMEV_INFO("Virtual PCI bus created (node %d)\n", nvmev_pci_sysdata.node);

	return bus;
};

struct nvmev_dev *VDEV_INIT(void)
{
	struct nvmev_dev *nvmev_vdev;
	nvmev_vdev = kzalloc(sizeof(*nvmev_vdev), GFP_KERNEL);

	nvmev_vdev->virtDev = kzalloc(PAGE_SIZE, GFP_KERNEL);

	nvmev_vdev->pcihdr = nvmev_vdev->virtDev + OFFS_PCI_HDR;
	nvmev_vdev->pmcap = nvmev_vdev->virtDev + OFFS_PCI_PM_CAP;
	// AOS: Add msi_cap
	nvmev_vdev->msicap = nvmev_vdev->virtDev + OFFS_PCI_MSI_CAP;
	nvmev_vdev->msixcap = nvmev_vdev->virtDev + OFFS_PCI_MSIX_CAP;
	nvmev_vdev->pciecap = nvmev_vdev->virtDev + OFFS_PCIE_CAP;
	nvmev_vdev->extcap = nvmev_vdev->virtDev + OFFS_PCI_EXT_CAP;

	nvmev_vdev->admin_q = NULL;
	nvmev_vdev->intr_thr =0;
	nvmev_vdev->intr_time = 0;

	return nvmev_vdev;
}

void VDEV_FINALIZE(struct nvmev_dev *nvmev_vdev)
{
	if (nvmev_vdev->msix_table)
		memunmap(nvmev_vdev->msix_table);

	if (nvmev_vdev->bar)
		memunmap(nvmev_vdev->bar);

	if (nvmev_vdev->old_bar)
		kfree(nvmev_vdev->old_bar);

	if (nvmev_vdev->old_dbs)
		kfree(nvmev_vdev->old_dbs);

	if (nvmev_vdev->admin_q) {
		if (nvmev_vdev->admin_q->nvme_cq)
			kfree(nvmev_vdev->admin_q->nvme_cq);

		if (nvmev_vdev->admin_q->nvme_sq)
			kfree(nvmev_vdev->admin_q->nvme_sq);

		kfree(nvmev_vdev->admin_q);
	}

	if (nvmev_vdev->virtDev)
		kfree(nvmev_vdev->virtDev);

	if (nvmev_vdev)
		kfree(nvmev_vdev);
}

static void PCI_HEADER_SETTINGS(struct pci_header *pcihdr, unsigned long base_pa)
{
	pcihdr->id.did = NVMEV_DEVICE_ID;
	pcihdr->id.vid = NVMEV_VENDOR_ID;
	/*
	pcihdr->cmd.id = 1;
	pcihdr->cmd.bme = 1;
	*/
	pcihdr->cmd.mse = 1;
	pcihdr->sts.cl = 1;

	pcihdr->htype.mfd = 0;
	pcihdr->htype.hl = PCI_HEADER_TYPE_NORMAL;

	pcihdr->rid = 0x01;

	pcihdr->cc.bcc = PCI_BASE_CLASS_STORAGE;
	pcihdr->cc.scc = 0x08;
	pcihdr->cc.pi = 0x02;

	pcihdr->mlbar.tp = PCI_BASE_ADDRESS_MEM_TYPE_64 >> 1;
	pcihdr->mlbar.ba = (base_pa & 0xFFFFFFFF) >> 14;

	pcihdr->mulbar = base_pa >> 32;

	pcihdr->ss.ssid = NVMEV_SUBSYSTEM_ID;
	pcihdr->ss.ssvid = NVMEV_SUBSYSTEM_VENDOR_ID;

	pcihdr->erom = 0x0;

	pcihdr->cap = OFFS_PCI_PM_CAP;

	pcihdr->intr.ipin = 0;
	pcihdr->intr.iline = NVMEV_INTX_IRQ;
}

static void PCI_PMCAP_SETTINGS(struct pci_pm_cap *pmcap)
{
	pmcap->pid.cid = PCI_CAP_ID_PM;
	pmcap->pid.next = OFFS_PCI_MSIX_CAP;

	pmcap->pc.vs = 3;
	pmcap->pmcs.nsfrst = 1;
	pmcap->pmcs.ps = PCI_PM_CAP_PME_D0 >> 16;
}

// AOS: Add msi_cap settings
static void PCI_MSICAP_SETTINGS(struct pci_msi_cap *msicap)
{
	msicap->mid.cid = PCI_CAP_ID_MSI;
	msicap->mid.next = OFFS_PCIE_CAP;
	// msicap->mid.next = OFFS_PCI_MSIX_CAP;

	msicap->mc.mme = 0b0;
	msicap->mc.mmc = 0b0;
	msicap->mc.c64 = 1;
	msicap->mc.pvm = 1; // Maskability
}

static void PCI_MSIXCAP_SETTINGS(struct pci_msix_cap *msixcap)
{
	msixcap->mxid.cid = PCI_CAP_ID_MSIX;
	msixcap->mxid.next = OFFS_PCIE_CAP;

	msixcap->mxc.mxe = 1;
	msixcap->mxc.ts = 127; // encoded as n-1

	msixcap->mtab.tbir = 0;
	msixcap->mtab.to = 0x400;

	msixcap->mpba.pbao = 0x1000;
	msixcap->mpba.pbir = 0;
}

static void PCI_PCIECAP_SETTINGS(struct pcie_cap *pciecap)
{
	pciecap->pxid.cid = PCI_CAP_ID_EXP;
	pciecap->pxid.next = 0x0;

	pciecap->pxcap.ver = PCI_EXP_FLAGS;
	pciecap->pxcap.imn = 0;
	pciecap->pxcap.dpt = PCI_EXP_TYPE_ENDPOINT;

	pciecap->pxdcap.mps = 1;
	pciecap->pxdcap.pfs = 0;
	pciecap->pxdcap.etfs = 1;
	pciecap->pxdcap.l0sl = 6;
	pciecap->pxdcap.l1l = 2;
	pciecap->pxdcap.rer = 1;
	pciecap->pxdcap.csplv = 0;
	pciecap->pxdcap.cspls = 0;
	pciecap->pxdcap.flrc = 1;
}

static void PCI_EXTCAP_SETTINGS(struct pci_ext_cap *ext_cap)
{
	off_t offset = 0;
	void *ext_cap_base = ext_cap;

	/* AER */
	ext_cap->cid = PCI_EXT_CAP_ID_ERR;
	ext_cap->cver = 1;
	ext_cap->next = PCI_CFG_SPACE_SIZE + 0x50;

	ext_cap = ext_cap_base + 0x50;
	ext_cap->cid = PCI_EXT_CAP_ID_VC;
	ext_cap->cver = 1;
	ext_cap->next = PCI_CFG_SPACE_SIZE + 0x80;

	ext_cap = ext_cap_base + 0x80;
	ext_cap->cid = PCI_EXT_CAP_ID_PWR;
	ext_cap->cver = 1;
	ext_cap->next = PCI_CFG_SPACE_SIZE + 0x90;

	ext_cap = ext_cap_base + 0x90;
	ext_cap->cid = PCI_EXT_CAP_ID_ARI;
	ext_cap->cver = 1;
	ext_cap->next = PCI_CFG_SPACE_SIZE + 0x170;

	ext_cap = ext_cap_base + 0x170;
	ext_cap->cid = PCI_EXT_CAP_ID_DSN;
	ext_cap->cver = 1;
	ext_cap->next = PCI_CFG_SPACE_SIZE + 0x1a0;

	ext_cap = ext_cap_base + 0x1a0;
	ext_cap->cid = PCI_EXT_CAP_ID_SECPCI;
	ext_cap->cver = 1;
	ext_cap->next = 0; 

	/*
	*(ext_cap + 1) = (struct pci_ext_cap) {
		.id = {
			.cid = 0xdead,
			.cver = 0xc,
			.next = 0xafe,
		},
	};

	PCI_CFG_SPACE_SIZE + ...;

	ext_cap = ext_cap + ...;
	ext_cap->id.cid = PCI_EXT_CAP_ID_DVSEC;
	ext_cap->id.cver = 1;
	ext_cap->id.next = 0;
	*/
}

bool NVMEV_PCI_INIT(struct nvmev_dev *nvmev_vdev)
{
	PCI_HEADER_SETTINGS(nvmev_vdev->pcihdr, nvmev_vdev->config.memmap_start);
	PCI_PMCAP_SETTINGS(nvmev_vdev->pmcap);
	// AOS: Add msi_cap
	PCI_MSICAP_SETTINGS(nvmev_vdev->msicap);
	PCI_MSIXCAP_SETTINGS(nvmev_vdev->msixcap);
	PCI_PCIECAP_SETTINGS(nvmev_vdev->pciecap);
	PCI_EXTCAP_SETTINGS(nvmev_vdev->extcap);

#ifdef CONFIG_NVMEV_FAST_X86_IRQ_HANDLING
	__init_apicid_to_cpuid();
#endif
	nvmev_vdev->intx_disabled = false;

	nvmev_vdev->virt_bus = __create_pci_bus();
	if (!nvmev_vdev->virt_bus)
		return false;
	
	init_coalesce_timer();

	return true;
}
