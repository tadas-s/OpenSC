/*
* This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "errors.h"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// FIXME: should wrap it with something like "if defined(ENABLE_SM) && defined(ENABLE_OPENPACE)"
// to skip it if there's no PACE thing enabled

#include "internal.h"
#include "pkcs15.h"

int sc_pkcs15emu_lteid_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
    if (p15card->card->type == SC_CARD_TYPE_LTEID)
        // return sc_pkcs15emu_lteid_init(p15card, aid);
        return SC_SUCCESS;

    return SC_ERROR_WRONG_CARD;
}