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

#include <stdlib.h>
#include <string.h>

#include "common/compat_strlcpy.h"

#include "internal.h"
#include "log.h"
#include "pkcs15.h"

static int sc_pkcs15emu_lteid_init(sc_pkcs15_card_t * p15card)
{
    // FIXME: values below hardcoded for quick test. It should really
    // be taken from DF02/5032 record.
    p15card->tokeninfo->version = 1;
    set_string(&p15card->tokeninfo->label, "First Last Names");
    set_string(&p15card->tokeninfo->manufacturer_id, "MaskTech GmbH");
    set_string(&p15card->tokeninfo->serial_number, "D461AB13BDB8D001");

    p15card->tokeninfo->flags = SC_PKCS15_TOKEN_PRN_GENERATION | SC_PKCS15_TOKEN_READONLY;

    /*
     * Signing certificate
     */
    struct sc_pkcs15_cert_info signing_certificate_info;
    struct sc_pkcs15_object signing_certificate_object;

    memset(&signing_certificate_info, 0, sizeof(signing_certificate_info));
    memset(&signing_certificate_object, 0, sizeof(signing_certificate_object));

    signing_certificate_info = (sc_pkcs15_cert_info_t) { .id = { .value = {1}, .len = 1 } };
    sc_format_path("3F00DF021F06", &signing_certificate_info.path);
    signing_certificate_object = (sc_pkcs15_object_t) { .label = "Elektroninio parašo sertifikatas" };

    LOG_TEST_RET(
        p15card->card->ctx,
        sc_pkcs15emu_add_x509_cert(p15card, &signing_certificate_object, &signing_certificate_info),
        "Error adding certificate."
    );

    /*
     * Authentication certificate
     */
    struct sc_pkcs15_cert_info authentication_certificate_info;
    struct sc_pkcs15_object authentication_certificate_object;

    memset(&authentication_certificate_info, 0, sizeof(authentication_certificate_info));
    memset(&authentication_certificate_object, 0, sizeof(authentication_certificate_object));

    authentication_certificate_info = (sc_pkcs15_cert_info_t) { .id = { .value = {2}, .len = 1 } };
    sc_format_path("3F00DF021F0A", &authentication_certificate_info.path);
    authentication_certificate_object = (sc_pkcs15_object_t) { .label = "Atpažinties sertifikatas" };

    LOG_TEST_RET(
        p15card->card->ctx,
        sc_pkcs15emu_add_x509_cert(p15card, &authentication_certificate_object, &authentication_certificate_info),
        "Error adding certificate."
    );

    /*
     * PIN
     */
    struct sc_pkcs15_auth_info pin_info = {
        .auth_id = { .len = 1, .value = { 1 } },
        .auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN,
        .attrs = {
            .pin = {
                .reference = 0x81,
                .flags = SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL,
                .type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
                .min_length = 6,
                .max_length = 12
            }
        },
        .tries_left = 3, // FIXME: should refresh
        .max_tries = 3
    };
    sc_format_path("3F00DF02", &pin_info.path);

    struct sc_pkcs15_object pin_obj = {
        .label = "PIN",
        .flags = SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL
    };

    LOG_TEST_RET(
        p15card->card->ctx,
        sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info),
        "Could not add pin object"
    );

    /*
     * PUK
     */
    struct sc_pkcs15_auth_info puk_info = {
        .auth_id = { .len = 1, .value = { 2 } },
        .auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN,
        .attrs = {
            .pin = {
                .reference = 0x4, // FIXME: unsure if correct
                .flags = SC_PKCS15_PIN_TYPE_FLAGS_PUK_LOCAL,
                .type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
                .min_length = 8,
                .max_length = 12
            }
        },
        .tries_left = 3, // FIXME: should refresh
        .max_tries = 3
    };
    sc_format_path("3F00DF02", &puk_info.path);

    struct sc_pkcs15_object puk_obj = {
        .label = "PUK",
        .flags = SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL
    };

    LOG_TEST_RET(
        p15card->card->ctx,
        sc_pkcs15emu_add_pin_obj(p15card, &puk_obj, &puk_info),
        "Could not add puk object"
    );

    /*
     * Signing private key
     */
    struct sc_pkcs15_prkey_info signing_prkey_info = {
        .id = {.len = 1, .value = { 1 }},
        .native = 1,
        .key_reference = 1,
        .field_length = 384, // FIXME: should be picked up from certificate?
        .usage = SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_DERIVE
    };

    struct sc_pkcs15_object signing_prkey_ojb = {
        .label = "Elektroninio parašo raktas",
        .auth_id = { .len = 1, .value = { 1 }},
        .user_consent = 0, // FIXME: ??...
        .flags = SC_PKCS15_CO_FLAG_PRIVATE
    };
    sc_format_path("3F00DF02", &signing_prkey_info.path);

    LOG_TEST_RET(
        p15card->card->ctx,
        sc_pkcs15emu_add_ec_prkey(p15card, &signing_prkey_ojb, &signing_prkey_info),
        "Could not add private key object"
    );

    /*
     * Authentication private key
     */
    struct sc_pkcs15_prkey_info authentication_prkey_info = {
        .id = {.len = 1, .value = { 2 }},
        .native = 1,
        .key_reference = 1,
        .field_length = 384, // FIXME: should be picked up from certificate?
        .usage = SC_PKCS15_PRKEY_USAGE_NONREPUDIATION
    };

    struct sc_pkcs15_object authentication_prkey_ojb = {
        .label = "Atpažinties raktas",
        .auth_id = { .len = 1, .value = { 1 }},
        .user_consent = 1, // FIXME: ??...
        .flags = SC_PKCS15_CO_FLAG_PRIVATE
    };
    sc_format_path("3F00DF02", &authentication_prkey_info.path);

    LOG_TEST_RET(
        p15card->card->ctx,
        sc_pkcs15emu_add_ec_prkey(p15card, &authentication_prkey_ojb, &authentication_prkey_info),
        "Could not add private key object"
    );

    LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}

int sc_pkcs15emu_lteid_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
    if (p15card->card->type == SC_CARD_TYPE_LTEID)
        return sc_pkcs15emu_lteid_init(p15card);

    return SC_ERROR_WRONG_CARD;
}