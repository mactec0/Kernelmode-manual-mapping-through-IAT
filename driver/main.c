#include "definitions.h"
#include "ioctls.h"

#define drv_device L"\\Device\\injdrv"
#define drv_dos_device L"\\DosDevices\\injdrv"
#define drv  L"\\Driver\\injdrv"

PDEVICE_OBJECT driver_object;
UNICODE_STRING dev, dos;

NTSTATUS unload_driver(PDRIVER_OBJECT driver);
NTSTATUS ioctl_create(PDEVICE_OBJECT device, PIRP irp); 
NTSTATUS ioctl_close(PDEVICE_OBJECT device, PIRP irp);
NTSTATUS io_device_control(PDEVICE_OBJECT device, PIRP Irp);
__inline NTSTATUS copy_memory(PEPROCESS src_proc, PEPROCESS target_proc, PVOID src, PVOID dst, SIZE_T size);
ULONGLONG get_module_handle(ULONG pid, LPCWSTR module_name);

NTSTATUS init(PDRIVER_OBJECT driver, PUNICODE_STRING path) { 
	RtlInitUnicodeString(&dev, drv_device);
	RtlInitUnicodeString(&dos, drv_dos_device);

	IoCreateDevice(driver, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &driver_object);
	IoCreateSymbolicLink(&dos, &dev);

	driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = io_device_control;
	driver->MajorFunction[IRP_MJ_CREATE] = ioctl_create;
	driver->MajorFunction[IRP_MJ_CLOSE] = ioctl_close;
	driver->DriverUnload = unload_driver;

	driver_object->Flags |= DO_DIRECT_IO;
	driver_object->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver,	PUNICODE_STRING path) { 
	NTSTATUS        status;
	UNICODE_STRING drv_name;
	RtlInitUnicodeString(&drv_name, drv);
	return IoCreateDriver(&drv_name, &init); 
}
 
NTSTATUS io_device_control(PDEVICE_OBJECT device, PIRP irp){
	NTSTATUS status;
	ULONG info_size = 0; 
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	ULONG control_code = stack->Parameters.DeviceIoControl.IoControlCode; 
	
	switch (control_code) {
	case ioctl_allocate_virtual_memory: {
			pk_alloc_mem_request in = (pk_alloc_mem_request)irp->AssociatedIrp.SystemBuffer;
			PEPROCESS target_proc;
			status = PsLookupProcessByProcessId(in->pid, &target_proc); 
			if (NT_SUCCESS(status)) {
				KAPC_STATE apc;
				KeStackAttachProcess(target_proc, &apc);
				status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &in->addr, 0, &in->size,
					in->allocation_type, in->protect);
				KeUnstackDetachProcess(&apc);
				ObfDereferenceObject(target_proc);
			} 
			info_size = sizeof(k_alloc_mem_request);
		} break;

	case ioctl_protect_virutal_memory: {
			pk_protect_mem_request in = (pk_protect_mem_request)irp->AssociatedIrp.SystemBuffer;
			PEPROCESS target_proc;
			status = PsLookupProcessByProcessId(in->pid, &target_proc);
			if (NT_SUCCESS(status)) {
				KAPC_STATE apc;
				ULONG old_protection;
				KeStackAttachProcess(target_proc, &apc);
				status = ZwProtectVirtualMemory(ZwCurrentProcess(), &in->addr, &in->size, in->protect, &old_protection);
				KeUnstackDetachProcess(&apc);
				in->protect = old_protection;
				ObfDereferenceObject(target_proc);
			}
			info_size = sizeof(k_protect_mem_request);
		} break;
	
	case ioctl_read_memory: {
			pk_rw_request in = (pk_rw_request)irp->AssociatedIrp.SystemBuffer;
			PEPROCESS target_proc; 
			status = PsLookupProcessByProcessId(in->pid, &target_proc);
			if (NT_SUCCESS(status)) {
				status = copy_memory(PsGetCurrentProcess(), target_proc, in->src, in->dst, in->size);
				ObfDereferenceObject(target_proc);
			} 
			info_size = sizeof(k_rw_request);
		} break;

	case ioctl_write_memory: {
			pk_rw_request in = (pk_rw_request)irp->AssociatedIrp.SystemBuffer;
			PEPROCESS target_proc; 
			status = PsLookupProcessByProcessId(in->pid, &target_proc);
			if (NT_SUCCESS(status)) {
				status = copy_memory(target_proc, PsGetCurrentProcess(), in->src, in->dst, in->size);
				ObfDereferenceObject(target_proc);
			}
			info_size = sizeof(k_rw_request);
		} break;

	case ioctl_get_module_base: {
			pk_get_base_module_request in = (pk_get_base_module_request)irp->AssociatedIrp.SystemBuffer;
			ULONGLONG handle = get_module_handle(in->pid, in->name);
			in->handle = handle;
			status = STATUS_SUCCESS;
			info_size = sizeof(k_get_base_module_request);
		} break;

	default:
			status = STATUS_INVALID_PARAMETER;
			info_size = 0;
		break;
	}


	irp->IoStatus.Status = status;
	irp->IoStatus.Information = info_size;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS unload_driver(PDRIVER_OBJECT driver) {
	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(driver->DeviceObject);
}

NTSTATUS ioctl_create(PDEVICE_OBJECT device, PIRP irp) {
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS ioctl_close(PDEVICE_OBJECT device, PIRP irp) {
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

__inline NTSTATUS copy_memory(PEPROCESS src_proc, PEPROCESS target_proc, PVOID src, PVOID dst, SIZE_T size) {
	PSIZE_T bytes;
	return MmCopyVirtualMemory(target_proc, src, src_proc, dst, size, UserMode, &bytes);
}

ULONGLONG get_module_handle(ULONG pid, LPCWSTR module_name) {
	PEPROCESS target_proc;
	ULONGLONG base = 0;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &target_proc)))
		return 0;

	KeAttachProcess((PKPROCESS)target_proc);

	PPEB peb = PsGetProcessPeb(target_proc);
	if (!peb)
		goto end;

	if (!peb->Ldr || !peb->Ldr->Initialized)
		goto end;


	UNICODE_STRING module_name_unicode;
	RtlInitUnicodeString(&module_name_unicode, module_name);
	for (PLIST_ENTRY list = peb->Ldr->InLoadOrderModuleList.Flink;
		list != &peb->Ldr->InLoadOrderModuleList;
		list = list->Flink) {
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (RtlCompareUnicodeString(&entry->BaseDllName, &module_name_unicode, TRUE) == 0) {
			base = entry->DllBase;
			goto end;
		}
	}

end:
	KeDetachProcess();
	ObDereferenceObject(target_proc);
	return base;
}
