/*
 * (C) Copyright 2020 Hewlett Packard Enterprise Development LP
 * Copyright (c) 2021 Amazon.com, Inc. or its affiliates.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "hmem.h"
#include "shared.h"

#ifdef HAVE_NEURON

#include <dlfcn.h>
#include <ft_list.h>

#include "nrt/nrt.h"
#include "nrt/nrt_experimental.h"

struct neuron_ops {
	NRT_STATUS (*nrt_tensor_allocate)(nrt_tensor_placement_t tensor_placement,
					  int logical_nc_id, size_t size,
					  const char *name, nrt_tensor_t **tensor);
	void (*nrt_tensor_free)(nrt_tensor_t **tensor);
	void *(*nrt_tensor_get_va)(const nrt_tensor_t *tensor);
	NRT_STATUS (*nrt_tensor_read)(const nrt_tensor_t *tensor, void *buf, size_t offset, size_t size);
	NRT_STATUS (*nrt_tensor_write)(nrt_tensor_t *tensor, const void *buf, size_t offset, size_t size);
	NRT_STATUS (*nrt_init)(nrt_framework_type_t framework, const char *fw_version, const char *fal_version);
};

static void *neuron_handle;
static struct neuron_ops neuron_ops;

/*
 * List to lookup the handle based on the pointer. Not optimal, but probably
 * fine for fabtests and this is better than changing the alloc/free functions
 * to pass a handle and pointer.
 */
struct nrt_allocation {
	nrt_tensor_t *tensor;
	void *ptr;
	size_t size;
	struct dlist_entry entry;
};
static struct dlist_entry nrt_alloc_list;

int ft_neuron_init(void)
{
	NRT_STATUS ret;

	neuron_handle = dlopen("libnrt.so", RTLD_NOW);
	if (!neuron_handle) {
		FT_ERR("Failed to dlopen libnrt.so\n");
		return -FI_ENOSYS;
	}

	neuron_ops.nrt_tensor_allocate = dlsym(neuron_handle, "nrt_tensor_allocate");
	if (!neuron_ops.nrt_tensor_allocate) {
		FT_ERR("Failed to find nrt_tensor_allocate\n");
		goto err;
	}

	neuron_ops.nrt_tensor_free = dlsym(neuron_handle, "nrt_tensor_free");
	if (!neuron_ops.nrt_tensor_free) {
		FT_ERR("Failed to find nrt_tensor_free\n");
		goto err;
	}

	neuron_ops.nrt_tensor_get_va = dlsym(neuron_handle, "nrt_tensor_get_va");
	if (!neuron_ops.nrt_tensor_get_va) {
		FT_ERR("Failed to find nrt_tensor_get_va\n");
		goto err;
	}

	neuron_ops.nrt_tensor_read = dlsym(neuron_handle, "nrt_tensor_read");
	if (!neuron_ops.nrt_tensor_read) {
		FT_ERR("Failed to find nrt_tensor_read\n");
		goto err;
	}

	neuron_ops.nrt_tensor_write = dlsym(neuron_handle, "nrt_tensor_write");
	if (!neuron_ops.nrt_tensor_write) {
		FT_ERR("Failed to find nrt_tensor_write\n");
		goto err;
	}

	neuron_ops.nrt_init = dlsym(neuron_handle, "nrt_init");
	if (!neuron_ops.nrt_init) {
		FT_ERR("Failed to find nrt_init\n");
		goto err;
	}

	dlist_init(&nrt_alloc_list);

	ret = neuron_ops.nrt_init(NRT_FRAMEWORK_TYPE_NO_FW, "2.0", "");
	if (ret != NRT_SUCCESS) {
		FT_ERR("Neuron init failed ret=%d\n", ret);
		goto err;
	}

	return FI_SUCCESS;
err:
	dlclose(neuron_handle);
	return -FI_ENODATA;
}

static void ft_neuron_free_region(struct nrt_allocation *region)
{
	neuron_ops.nrt_tensor_free(&region->tensor);
	dlist_remove(&region->entry);
	free(region);
}

static ssize_t ft_neuron_find_region(void *buf, struct nrt_allocation **region)
{
	*region = NULL;

	dlist_foreach_container(&nrt_alloc_list, struct nrt_allocation,
	                        *region, entry)
		if (buf >= (*region)->ptr &&
		    (char *)buf < ((char *)(*region)->ptr) + (*region)->size)
			break;

	if (!(*region))
		return -1;

	return ((uintptr_t)buf - (uintptr_t)(*region)->ptr);
}

int ft_neuron_cleanup(void)
{
	struct nrt_allocation *region;
	struct dlist_entry *tmp;

	dlist_foreach_container_safe(&nrt_alloc_list, struct nrt_allocation,
	                             region, entry, tmp)
		ft_neuron_free_region(region);

	dlclose(neuron_handle);
	return 0;
}

int ft_neuron_alloc(uint64_t device, void **buf, size_t size)
{
	struct nrt_allocation *region;
	int page_size;
	int ret = 0;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size == -1) {
		FT_PRINTERR("failed to get pagesize\n", -errno);
		return -FI_EINVAL;
	}
	size = (size + (page_size - 1)) & ~(page_size - 1);

	region = malloc(sizeof(struct nrt_allocation));
	if (!region)
		return -FI_ENOMEM;

	ret = neuron_ops.nrt_tensor_allocate(NRT_TENSOR_PLACEMENT_DEVICE, device,
	                                     size, "fabtests", &region->tensor);
	if (ret) {
		FT_ERR("nrt_tensor_allocate ret=%d\n", ret);
		free(region);
		return -FI_ENOMEM;
	}

	region->ptr = neuron_ops.nrt_tensor_get_va(region->tensor);
	if (!region->ptr) {
		FT_ERR("nrt_tensor_get_va failed\n");
		neuron_ops.nrt_tensor_free(&region->tensor);
		free(region);
		return -FI_ENOMEM;
	}

	region->size = size;
	*buf = region->ptr;
	dlist_insert_tail(&region->entry, &nrt_alloc_list);

	return 0;
}

int ft_neuron_free(void *buf)
{
	struct nrt_allocation *region;

	ft_neuron_find_region(buf, &region);

	if (!region)
		return -FI_EINVAL;

	ft_neuron_free_region(region);

	return 0;
}

int ft_neuron_memset(uint64_t device, void *buf, int value, size_t size)
{
	struct nrt_allocation *region;

	ft_neuron_find_region(buf, &region);

	if (!region)
		return -FI_EINVAL;

	/* TODO: no memset op, maybe just call write? */

	return 0;
}

int ft_neuron_memcpy_to_hmem(uint64_t device, void *dst, const void *src,
			     size_t size)
{
	struct nrt_allocation *region;
	ssize_t offset;
	NRT_STATUS ret;

	offset = ft_neuron_find_region(dst, &region);

	if (!region || offset < 0)
		return -FI_EINVAL;

	ret = neuron_ops.nrt_tensor_write(region->tensor, src, offset, size);
	if (ret) {
		FT_ERR("nrt_tensor_write failed ret=%d\n", ret);
		return -FI_EIO;
	}

	return 0;
}

int ft_neuron_memcpy_from_hmem(uint64_t device, void *dst, const void *src,
			       size_t size)
{
	struct nrt_allocation *region;
	ssize_t offset;
	NRT_STATUS ret;

	offset = ft_neuron_find_region((void *)src, &region);

	if (!region || offset < 0)
		return -FI_EINVAL;

	ret = neuron_ops.nrt_tensor_read(region->tensor, dst, offset, size);
	if (ret) {
		FT_ERR("nrt_tensor_read failed ret=%d\n", ret);
		return -FI_EIO;
	}

	return 0;
}

#else

int ft_neuron_init(void)
{
	return -FI_ENOSYS;
}

int ft_neuron_cleanup(void)
{
	return -FI_ENOSYS;
}

int ft_neuron_alloc(uint64_t device, void **buf, size_t size)
{
	return -FI_ENOSYS;
}

int ft_neuron_free(void *buf)
{
	return -FI_ENOSYS;
}

int ft_neuron_memset(uint64_t device, void *buf, int value, size_t size)
{
	return -FI_ENOSYS;
}

int ft_neuron_memcpy_to_hmem(uint64_t device, void *dst, const void *src,
			     size_t size)
{
	return -FI_ENOSYS;
}

int ft_neuron_memcpy_from_hmem(uint64_t device, void *dst, const void *src,
			       size_t size)
{
	return -FI_ENOSYS;
}
#endif /*_HAVE_NEURON_H */
