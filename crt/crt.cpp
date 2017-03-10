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

#include <bfgsl.h>
#include <bfsupport.h>
#include <bfconstants.h>
#include <bfehframelist.h>

typedef void (*init_t)();
typedef void (*fini_t)();

int
main(int argc, const char *argv[]);

void *__dso_handle = 0;

auto __g_eh_frame_list_num = 0ULL;
eh_frame_t __g_eh_frame_list[MAX_NUM_MODULES] = {};

extern "C" struct eh_frame_t *
get_eh_frame_list() noexcept
{
    return __g_eh_frame_list;
}

extern "C" void
__bareflank_init(section_info_t *info) noexcept
{
    if (info->init_addr != nullptr) {
        reinterpret_cast<init_t>(info->init_addr)();
    }

    if (info->init_array_addr != nullptr) {
        auto n = info->init_array_size >> 3;
        auto init_array = static_cast<init_t *>(info->init_array_addr);

        for (auto i = 0U; i < n && gsl::at(init_array, n, i) != nullptr; i++) {
            gsl::at(init_array, n, i)();
        }
    }
}

extern "C" void
__bareflank_fini(section_info_t *info) noexcept
{
    if (info->fini_array_addr != nullptr) {
        auto n = info->fini_array_size >> 3;
        auto fini_array = static_cast<fini_t *>(info->fini_array_addr);

        for (auto i = 0U; i < n && gsl::at(fini_array, n, i) != nullptr; i++) {
            gsl::at(fini_array, n, i)();
        }
    }

    if (info->fini_addr != nullptr) {
        reinterpret_cast<fini_t>(info->fini_addr)();
    }
}

extern "C" void
__bareflank_register_eh_frame(section_info_t *info) noexcept
{
    gsl::at(__g_eh_frame_list, __g_eh_frame_list_num).addr = info->eh_frame_addr;
    gsl::at(__g_eh_frame_list, __g_eh_frame_list_num).size = info->eh_frame_size;
    __g_eh_frame_list_num++;
}

extern "C" int
_start_c(crt_info_t *info) noexcept
{
    // TODO:
    //
    // - Need to set the program break here.
    // - Need to put into the info struct whether to run exit(ret) or to
    //   actually return
    //

    for (auto i = 0; i < info->info_num; i++) {
        auto sinfo = &gsl::at(info->info, i);

        __bareflank_init(sinfo);
        __bareflank_register_eh_frame(sinfo);
    }

    auto ret = main(info->argc, info->argv);

    for (auto i = 0; i < info->info_num; i++) {
        auto sinfo = &gsl::at(info->info, i);

        __bareflank_fini(sinfo);
    }

    return ret;
}
