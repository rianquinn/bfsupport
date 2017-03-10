//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#define NEED_GSL_LITE

#include <stddef.h>
#include <stdint.h>

#include <bfgsl.h>
#include <dummy_libs.h>

derived1 g_derived1;
derived2 g_derived2;

int
main(int argc, char *argv[])
{
    ignored(argc);
    ignored(argv);

    return g_derived1.foo(atoi(argv[0])) + g_derived2.foo(atoi(argv[1]));
}

// -----------------------------------------------------------------------------
// Missing C Functions
// -----------------------------------------------------------------------------

int g_cursor = 0;
char g_memory[0x1000] = {};

extern "C" int
write(int file, const void *buffer, size_t count)
{
    ignored(file);
    ignored(buffer);
    ignored(count);

    return 0;
}

extern "C" void *
_malloc_r(struct _reent *ent, size_t size)
{
    ignored(ent);

    auto *addr = &g_memory[g_cursor];
    g_cursor += size;

    return addr;
}

extern "C" void
_free_r(struct _reent *ent, void *ptr)
{
    ignored(ent);
    ignored(ptr);
}

extern "C" void *
_calloc_r(struct _reent *ent, size_t nmemb, size_t size)
{
    ignored(ent);
    ignored(nmemb);
    ignored(size);

    return nullptr;
}

extern "C" void *
_realloc_r(struct _reent *ent, void *ptr, size_t size)
{
    ignored(ent);
    ignored(ptr);
    ignored(size);

    return nullptr;
}
