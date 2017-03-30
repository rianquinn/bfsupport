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

#include <bfgsl.h>
#include <bfexports.h>

#include <exception>
#include <dummy_libs.h>

derived1 g_derived1;
derived2 g_derived2;

int
main(int argc, char *argv[])
{
    ignored(argc);
    ignored(argv);

    try {
        throw std::runtime_error("test exceptions");
    }
    catch(std::exception &)
    { }

    return g_derived1.foo(atoi(argv[0])) + g_derived2.foo(atoi(argv[1]));
}

// -----------------------------------------------------------------------------
// Missing C Functions
// -----------------------------------------------------------------------------

int g_cursor = 0;
char g_memory[0x10000] = {};

extern "C" EXPORT_SYM int
write(int file, const void *buffer, size_t count)
{
    ignored(file);
    ignored(buffer);
    ignored(count);

    return 0;
}

extern "C" EXPORT_SYM void *
_malloc_r(struct _reent *ent, size_t size)
{
    ignored(ent);

    auto *addr = &g_memory[g_cursor];
    g_cursor += size;

    return addr;
}

extern "C" EXPORT_SYM void
_free_r(struct _reent *ent, void *ptr)
{
    ignored(ent);
    ignored(ptr);
}

extern "C" EXPORT_SYM void *
_calloc_r(struct _reent *ent, size_t nmemb, size_t size)
{
    ignored(ent);

    if (auto ptr = malloc(nmemb * size)) {
        return memset(ptr, 0, nmemb * size);
    }

    return nullptr;
}

extern "C" EXPORT_SYM void *
_realloc_r(struct _reent *ent, void *ptr, size_t size)
{
    ignored(ent);
    ignored(ptr);
    ignored(size);

    return nullptr;
}
