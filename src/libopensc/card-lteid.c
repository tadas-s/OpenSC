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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(ENABLE_SM) && defined(ENABLE_OPENPACE)

#include "libopensc/internal.h"
#include "libopensc/opensc.h"
#include "libopensc/pace.h"
#include "libopensc/sm.h"
#include "libopensc/asn1.h"
#include "sm/sm-eac.h"
#include <string.h>
#include <stdlib.h>

static const struct sc_card_operations *iso_ops = NULL;
static struct sc_card_operations lteid_ops;

static struct sc_card_driver lteid_drv = {
	"Lithuanian eID card (asmens tapatybės kortelė)",
	"lteid",
	&lteid_ops,
	NULL, 0, NULL
};

struct lteid_drv_data {
	unsigned char pace;
	unsigned char pace_pin_ref;
};

static const struct sc_atr_table lteid_atrs[] = {
	{ "3b:9d:18:81:31:fc:35:80:31:c0:69:4d:54:43:4f:53:73:02:06:05:d0", NULL, NULL, SC_CARD_TYPE_LTEID, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

struct lteid_buff {
	u8 val[SC_MAX_APDU_RESP_SIZE];
	size_t len;
};

static int lteid_match_card(sc_card_t* card) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (_sc_match_atr(card, lteid_atrs, &card->type) >= 0) {
		sc_log(card->ctx, "ATR recognized as Lithuanian eID card.");
		LOG_FUNC_RETURN(card->ctx, 1);
	}
	LOG_FUNC_RETURN(card->ctx, 0);
}

static int lteid_get_can(sc_card_t* card, struct establish_pace_channel_input* pace_input) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	const char* can;

	can = getenv("LTEID_CAN");

	if (!can || can[0] == '\0') {
		for (size_t i = 0; card->ctx->conf_blocks[i]; ++i) {
			scconf_block** blocks = scconf_find_blocks(card->ctx->conf, card->ctx->conf_blocks[i], "card_driver", "lteid");
			if (!blocks)
				continue;
			for (size_t j = 0; blocks[j]; ++j)
				if ((can = scconf_get_str(blocks[j], "can", NULL)))
					break;
			free(blocks);
		}
	}

	if (!can || 6 != strlen(can)) {
		sc_log(card->ctx, "Missing or invalid CAN. 6 digits required.");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
	}

	pace_input->pin_id = PACE_PIN_ID_CAN;
	pace_input->pin = (const unsigned char*)can;
	pace_input->pin_length = 6;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

// Mostly taken from `dtrust_perform_pace`
static int lteid_perform_pace(struct sc_card *card, const int ref, const unsigned char *pin, size_t pinlen, int *tries_left) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	struct lteid_drv_data *drv_data = card->drv_data;
	struct establish_pace_channel_input pace_input = {0};
	struct establish_pace_channel_output pace_output = {0};

	if (drv_data->pace && drv_data->pace_pin_ref != ref) {
		sc_log(card->ctx, "Re-opening PACE with pin ref 0x%02x. Previous pin ref: 0x%02x.", ref, drv_data->pace_pin_ref);
		sc_sm_stop(card);
	}

	if (ref == PACE_PIN_ID_CAN) {
		if (SC_SUCCESS != lteid_get_can(card, &pace_input)) {
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
		}
	} else {
		pace_input.pin_id = ref;
		pace_input.pin = pin;
		pace_input.pin_length = pinlen;
	}

	// FIXME: figure out error handling for incorrect pin. Otherwise connection is irrecoverably broken.
	if (SC_SUCCESS != perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02)) {
		sc_log(card->ctx, "Error performing PACE for pin ref 0x%02x.", ref);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
	}

	// Track PACE status
	drv_data->pace = 1;
	drv_data->pace_pin_ref = ref;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int lteid_unlock(sc_card_t* card) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	// if (SC_SUCCESS != lteid_perform_pace(card, PACE_PIN_ID_PIN, NULL, 0, NULL)) {
	if (SC_SUCCESS != lteid_perform_pace(card, PACE_PIN_ID_CAN, NULL, 0, NULL)) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int lteid_init(sc_card_t* card) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	struct lteid_drv_data *drv_data = calloc(1, sizeof(struct lteid_drv_data));

	if (drv_data == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	drv_data->pace = 0;
	drv_data->pace_pin_ref = 0;
	card->drv_data = drv_data;

	memset(&card->sm_ctx, 0, sizeof card->sm_ctx);

	card->max_send_size = 65535;
	card->max_recv_size = 65535;
	card->caps |= SC_CARD_CAP_ISO7816_PIN_INFO | SC_CARD_CAP_APDU_EXT;

	LOG_TEST_RET(card->ctx, sc_enum_apps(card), "Enumerate apps failed");

	LOG_TEST_RET(card->ctx, lteid_unlock(card), "Unlock card failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int lteid_logout(sc_card_t* card) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_sm_stop(card);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int lteid_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	struct lteid_drv_data *drv_data = card->drv_data;
	int rv;

	sc_log(card->ctx, "== lteid_pin_cmd ===============================");
	sc_log(card->ctx, "PIN cmd: %i", data->cmd);
	sc_log(card->ctx, "PIN reference: %i", data->pin_reference);
	sc_log(card->ctx, "PIN type: %i", data->pin_type);
	if (data->pin1.data != NULL && data->pin1.len == 6) {
		sc_log(card->ctx, "PIN: '%.6s'", data->pin1.data);
	}
	sc_log(card->ctx, "================================================");

	// FIXME: Limit to PACE pin references only?.. There's the 0x81 pin which is not PACE pin.
	if (data->cmd == SC_PIN_CMD_VERIFY) {
		rv = lteid_perform_pace(card, data->pin_reference, data->pin1.data, data->pin1.len, tries_left);

		LOG_FUNC_RETURN(card->ctx, rv);
	}

	if (data->cmd == SC_PIN_CMD_GET_INFO) {
		// For now just pretend we got the information
		// *tries_left = 3;
		data->pin1.max_tries = 3;
		data->pin1.tries_left = 3;

		// Log in via Firefox PKCS11 module dialog works with this. Not sure yet how to log out.
		data->pin1.logged_in = (drv_data->pace_pin_ref == data->pin_reference);

		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}

	rv = iso_ops->pin_cmd(card, data, tries_left);

	LOG_FUNC_RETURN(card->ctx, rv);
}

static int lteid_set_security_env(struct sc_card *card, const struct sc_security_env *env, int se_num) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	int rv = iso_ops->set_security_env(card, env, se_num);

	LOG_FUNC_RETURN(card->ctx, rv);
}

static int lteid_compute_signature(struct sc_card *card, const u8 * data, size_t data_len, u8 * out, size_t outlen) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	int rv = iso_ops->compute_signature(card, data, data_len, out, outlen);

	LOG_FUNC_RETURN(card->ctx, rv);
}

struct sc_card_driver* sc_get_lteid_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;

	lteid_ops = *iso_ops;
	lteid_ops.match_card = lteid_match_card;
	lteid_ops.init = lteid_init;
	// lteid_ops.select_file = lteid_select_file;
	lteid_ops.set_security_env = lteid_set_security_env;
	lteid_ops.compute_signature = lteid_compute_signature;
	lteid_ops.pin_cmd = lteid_pin_cmd;
	lteid_ops.logout = lteid_logout;

	return &lteid_drv;
}

#else

#include "libopensc/opensc.h"

struct sc_card_driver* sc_get_lteid_driver(void) {
	return NULL;
}

#endif