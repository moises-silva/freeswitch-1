/* 
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2014, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 * 
 * Anthony Minessale II <anthm@freeswitch.org>
 *
 *
 * sofia_media.c -- SOFIA SIP Endpoint (sofia media code)
 *
 */
#include "mod_sofia.h"




uint8_t sofia_media_negotiate_sdp(switch_core_session_t *session, const char *r_sdp, switch_sdp_type_t type)
{
	uint8_t t, p = 0;
	private_object_t *tech_pvt = switch_core_session_get_private(session);

	if ((t = switch_core_media_negotiate_sdp(session, r_sdp, &p, type))) {
		sofia_set_flag_locked(tech_pvt, TFLAG_SDP);
	}

	if (!p) {
		sofia_set_flag(tech_pvt, TFLAG_NOREPLY);
	}

	return t;
}

switch_status_t sofia_media_activate_rtp(private_object_t *tech_pvt)
{
	switch_status_t status;

	switch_mutex_lock(tech_pvt->sofia_mutex);
	status = switch_core_media_activate_rtp(tech_pvt->session);
	switch_mutex_unlock(tech_pvt->sofia_mutex);


	if (status == SWITCH_STATUS_SUCCESS) {
		sofia_set_flag(tech_pvt, TFLAG_RTP);
		sofia_set_flag(tech_pvt, TFLAG_IO);
	}

	return status;
}



switch_status_t sofia_media_tech_media(private_object_t *tech_pvt, const char *r_sdp)
{
	uint8_t match = 0;

	switch_assert(tech_pvt != NULL);
	switch_assert(r_sdp != NULL);

	if (zstr(r_sdp)) {
		return SWITCH_STATUS_FALSE;
	}

	if ((match = sofia_media_negotiate_sdp(tech_pvt->session, r_sdp, SDP_TYPE_REQUEST))) {
		if (switch_core_media_choose_port(tech_pvt->session, SWITCH_MEDIA_TYPE_AUDIO, 0) != SWITCH_STATUS_SUCCESS) {
			return SWITCH_STATUS_FALSE;
		}
		if (sofia_media_activate_rtp(tech_pvt) != SWITCH_STATUS_SUCCESS) {
			return SWITCH_STATUS_FALSE;
		}
		switch_channel_set_variable(tech_pvt->channel, SWITCH_ENDPOINT_DISPOSITION_VARIABLE, "EARLY MEDIA");
		sofia_set_flag_locked(tech_pvt, TFLAG_EARLY_MEDIA);
		switch_channel_mark_pre_answered(tech_pvt->channel);
		return SWITCH_STATUS_SUCCESS;
	}


	return SWITCH_STATUS_FALSE;
}

static void process_mp(switch_core_session_t *session, switch_stream_handle_t *stream, const char *boundary, const char *str) {
	char *dname = switch_core_session_strdup(session, str);
	char *dval;

	if ((dval = strchr(dname, ':'))) {
		*dval++ = '\0';
		if (*dval == '~') {
			stream->write_function(stream, "--%s\r\nContent-Type: %s\r\nContent-Length: %d\r\n%s\r\n", boundary, dname, strlen(dval), dval + 1);
		} else {
			stream->write_function(stream, "--%s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s\r\n", boundary, dname, strlen(dval) + 1, dval);
		}							
	}
}

#ifdef SOFIA_ISUP
static uint32_t bcd_len(const char *num)
{
	// if the number of digits is even, we divide by 2 and take that
	// if it's odd, we add 1 because of the required spare filling
	uint32_t numlen = strlen(num);
	uint32_t len = (numlen / 2);
	if ((numlen % 2)) {
		len += 1;
	}
	return len;
}

const char *sofia_media_decode_isup_number(switch_core_session_t *session, uint8_t *number, uint8_t *nai, uint8_t *inni, uint8_t *numbering_plan)
{
	uint8_t octet, bufidx;
	uint8_t length = number[0]; // first octet is the length
	// second octet is the odd/even indicator and nai
	uint8_t is_even = ((number[1] & 0x80) == 0);
	char *numbuf;

	// get the nai now
	*nai = (number[1] & 0x7F);

	// the third octet contains inn indicator and numbering plan
	*inni = (number[2] & 0x80) ? 1 : 0;
	*numbering_plan = ((number[2] & 0x70) >> 4);

	// start decoding the address signals at the fourth octet (third
	// octet if we don't count the length as part of the parameter as in
	// figure C-9 section C 3.7 of the Q.767 spec
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
					  "[isup] Found isup number of length %d\n", length);
	// length * 2 is actually more than we need since the length
	// includes 2 other octets that are not address signals
	numbuf = switch_core_session_alloc(session, length * 2);
	octet = 3;
	bufidx = 0;
	length -= 2; // remove the 2 non-signal octets from the length
	while (length) {
		bufidx += sprintf(&numbuf[bufidx], "%d", (number[octet] & 0x0F));
		if (is_even || length > 1) {
			bufidx += sprintf(&numbuf[bufidx], "%d", (number[octet] >> 4));
		}
		length -= 1;
		octet++;
	}
	return numbuf;
}

uint8_t *sofia_media_encode_isup_number(switch_core_session_t *session,
		                                const char *number,
										uint8_t nai,
										uint8_t inni,
										uint8_t numbering_plan)
{
	uint8_t octet, is_even;
	const char *digit;
	size_t encoded_len = bcd_len(number) + 3;
	uint8_t *encoded_number = switch_core_session_alloc(session, encoded_len);

	// set the length
	encoded_number[0] = (encoded_len - 1);

	// set the nai in the second octet
	encoded_number[1] |= (nai & 0x7F);

	// the third octet contains inn indicator and numbering plan
	encoded_number[2] |= ((inni << 7) & 0x80);
	encoded_number[2] |= ((numbering_plan << 4) & 0x70);

	// start encoding the address signals at the fourth octet (third
	// octet if we don't count the length as part of the parameter as in
	// figure C-9 section C 3.7 of the Q.767 spec
	octet = 3;
	is_even = 1;
	digit = number;
	while (*digit) {
		if (!isdigit(*digit)) {
			// ignore any non-digit
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING,
							  "[isup] Cannot encode non-digit character %c\n", *digit);
			digit++;
			continue;
		}
		if (is_even) {
			encoded_number[octet] |= (*digit & 0x0F);
			is_even = 0;
		} else {
			encoded_number[octet] |= ((*digit << 4) & 0xF0);
			is_even = 1;
			octet++;
		}
		digit++;
	}
	// set the even/odd indicator
	encoded_number[1] |= (((is_even == 0) << 7) & 0x80);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
					  "[isup] Encoded isup number of length %zd in %zd bytes\n", strlen(number), (encoded_len - 3));
	return encoded_number;
}

// Refer to table C-16 of the Q.767 spec, but basically an IAM is
// composed as a set of fixed length mandatory paramaters:
// - message type, nature of connection indicators,
//   forward call indicators, calling party category
// Then followed by a single mandatory parameter of variable length:
// - called party number
// Then followed by optional parameters of variable length:
// - calling party number
// - optional forward call indicators
// Note that the order of the optional parameters is not guaranteed, so
// inside the byte stream you can get first the optional forward call
// indicators and then the calling party number or viceversa. Here we're
// only interested at the moment my the calling party number, which is
// identified by the type 10 and described in section C 3.8
#define isup_calling_party_category_offset 0x4
#define isup_called_number_pointer_offset 0x6
#define isup_optional_parameters_pointer_offset 0x7
#define isup_calling_number_parameter_id 0xa
#define isup_mandatory_fixed_parameters_len 8
#define safe_strlen(ptr) ptr ? strlen(ptr) : 0
void *sofia_media_manipulate_isup_iam(switch_core_session_t *session, switch_channel_t *channel,
		                          uint8_t *isup_payload, size_t isup_len, size_t *new_isup_len)
{
#define debug 0
#if debug
	int i = 0;
#endif
	uint32_t payload_idx;
	size_t new_len;
	uint8_t *new_isup_payload;
	uint32_t called_number_ptr, optional_parameters_ptr;
	uint8_t *called_number, *calling_number, *optional_parameters;
	const char *user_cpc, *user_called_number, *user_calling_number;
	size_t optional_parameters_len;
	uint8_t calling_nai, calling_inni, calling_numbering_plan, called_nai, called_inni, called_numbering_plan;
	const char *calling_number_s, *called_number_s;

	// collect the parameters we allow to manipulate (currently just cpc and called/calling numbers)
	user_cpc = switch_channel_get_variable(channel, "sip_isup_iam_calling_party_category");
	user_called_number = switch_channel_get_variable(channel, "sip_isup_iam_called_number");
	user_calling_number = switch_channel_get_variable(channel, "sip_isup_iam_calling_number");

#if debug
	{
		switch_stream_handle_t stream = { 0 };
		SWITCH_STANDARD_STREAM(stream);
		for (i = 0; i <= isup_len; i++) {
			stream.write_function(&stream, "0x%X ", isup_payload[i]);
			if (i && !(i % 8)) {
				stream.write_function(&stream, "\n");
			}
		}
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT,
						  "[isup] %s\n", (char *)stream.data);
		switch_safe_free(stream.data);
	}
#endif
	// The called number is a fixed mandatory variable parameter
	// so we know it'll always be in the same place, we just need to
	// find the pointer to it
	called_number_ptr = isup_payload[isup_called_number_pointer_offset];
	called_number = &isup_payload[isup_called_number_pointer_offset + called_number_ptr];
	called_number_s = sofia_media_decode_isup_number(session, called_number, &called_nai, &called_inni, &called_numbering_plan);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
					 "[isup] Decoded called number: %s (nai=%u, inni=%u, plan=%u)\n",
					 called_number_s, called_nai, called_inni, called_numbering_plan);

	// Find the calling number in the optional parameters
	optional_parameters_ptr = isup_payload[isup_optional_parameters_pointer_offset];
	optional_parameters = &isup_payload[isup_optional_parameters_pointer_offset + optional_parameters_ptr];
	// iterate over optional parameters until we find the calling number or run out of parameters
	calling_number = NULL;
	optional_parameters_len = 1; // always at least one (one octet with 0x00 if no optional parameters are present)
	while (optional_parameters[0]) {
		if (optional_parameters[0] != isup_calling_number_parameter_id) {
			// this is not the calling number
			// count the extra parameters length for our new isup payload calculation
			// 1 octet for the type
			// 1 octet for the length
			// N octets for the actual payload (its length is specified by the length octet)
			optional_parameters_len += 2 + optional_parameters[1];
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
							  "[isup] Ignoring parameter type: %d\n", optional_parameters[0]);
		} else {
			// found the calling number parameter, skip the type and point to its length
			calling_number = &optional_parameters[1];
		}
		// skip the parameter contents and we'll get to the next parameter type
		optional_parameters = &optional_parameters[2 + optional_parameters[1]];
	}

	if (calling_number) {
		calling_number_s = sofia_media_decode_isup_number(session, calling_number, &calling_nai, &calling_inni, &calling_numbering_plan);
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
						  "[isup] Decoded calling number: %s (nai=%u, inni=%u, plan=%u)\n",
						  calling_number_s, calling_nai, calling_inni, calling_numbering_plan);
	}

	// Now we have all the information to allocate a new isup buffer
	// allocate enough space to fit the new IAM
	// right off the bat, we start with 8 from the fixed length parameters
	// 00 (message type)
	// 01 (nature of connection indicators)
	// 0203 (forward call indicators)
	// 04 (calling party category)
	// 05 (transmission medium requirement)
	// 06 (pointer to parameter)
	// 07 (pointer to start of optional part)
	new_len = isup_mandatory_fixed_parameters_len;
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
					  "[isup] isup length started as: %zd\n", new_len);

	// Now the length of the called number (it's a mandatory variable length parameter)
	// we either use the existing IAM parameter length, or if the user
	// specified one, we use their length
	if (user_called_number) {
		// the length is the length octet + 2 octets for the odd/even
		// indicator, NAI, INN and numbering plan + the digits length
		new_len += 3 + bcd_len(user_called_number);
	} else {
		// use whatever existing length comes in the IAM
		new_len += (1 + called_number[0]); // length octet + the specified parameter length
	}
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
					  "[isup] isup length after adding called number: %zd\n", new_len);

	// Now the length of the calling number
	// since this is an optional variable length parameter
	// we have to check if it is present at all
	if (user_calling_number) {
		// the length is the type octet + length octet + 2 octets for the odd/even
		new_len += 4 + bcd_len(user_calling_number);
	} else if (calling_number) {
		// use the existing length, if any
		new_len += (2 + calling_number[0]); // type octet + length octet + the specified parameter length
	}
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
					  "[isup] isup length after adding calling number: %zd\n", new_len);

	// finally add the lenght of the extra parameters if any
	new_len += optional_parameters_len;

	// allocate the new isup payload buffer
	new_isup_payload = switch_core_session_alloc(session, new_len);
	*new_isup_len = new_len;
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
					  "[isup] New isup length calculated as: %zd\n", new_len);

	// copy the first fixed part of the IAM
	payload_idx = 0;
	memcpy(&new_isup_payload[payload_idx], isup_payload, isup_mandatory_fixed_parameters_len);
	payload_idx += isup_mandatory_fixed_parameters_len;

	// Manipulate the cpc if specified
	if (user_cpc) {
		new_isup_payload[isup_calling_party_category_offset] = (uint8_t)atoi(user_cpc);
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
						  "[isup] Set outbound cpc to %d\n", new_isup_payload[isup_calling_party_category_offset]);
	} else {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
						  "[isup] No outbound cpc specified, keeping original %d\n",
						  new_isup_payload[isup_calling_party_category_offset]);
	}

	// Manipulate the called number if specified
	if (user_called_number) {
		// override the called number with the encoded number
		called_number = sofia_media_encode_isup_number(session, user_called_number, called_nai, called_inni, called_numbering_plan);
		// we have to fix the optional parameter index
		// because that depends on the length of the called number parameter
		new_isup_payload[isup_optional_parameters_pointer_offset] = (called_number[0] + 2);
	}
	// Copy the called number into the new isup payload
	memcpy(&new_isup_payload[payload_idx], called_number, (1 + called_number[0]));
	payload_idx += (1 + called_number[0]);

	// Copy all optional parameters, manipulating the calling number if present
	optional_parameters = &isup_payload[isup_optional_parameters_pointer_offset + optional_parameters_ptr];
	while (optional_parameters[0]) {
		uint32_t parameter_len = 2 + optional_parameters[1]; // type octet, length octet + payload length specified in the length octet
		if (!user_calling_number || optional_parameters[0] != isup_calling_number_parameter_id) {
			// this is not the calling number (or it is, but we don't
			// care cuz the user didn't specify one of its own)
			// copy this parameter into the new isup payload
			memcpy(&new_isup_payload[payload_idx], optional_parameters, parameter_len);
			payload_idx += parameter_len;
		} else {
			calling_number = sofia_media_encode_isup_number(session, user_calling_number, calling_nai, calling_inni, calling_numbering_plan);
			new_isup_payload[payload_idx] = isup_calling_number_parameter_id;
			payload_idx++;
			memcpy(&new_isup_payload[payload_idx], calling_number, (1 + calling_number[0]));
			payload_idx += (1 + calling_number[0]);
		}
		// skip the parameter contents and we'll get to the next parameter type
		optional_parameters = &optional_parameters[parameter_len];
	}
#if debug
	{
		switch_stream_handle_t stream = { 0 };
		SWITCH_STANDARD_STREAM(stream);
		for (i = 0; i <= new_len; i++) {
			stream.write_function(&stream, "0x%X ", new_isup_payload[i]);
			if (i && !(i % 8)) {
				stream.write_function(&stream, "\n");
			}
		}
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT,
						  "[isup] %s\n", (char *)stream.data);
		switch_safe_free(stream.data);
	}
#endif
	return new_isup_payload;
}
#endif

sip_payload_t *sofia_media_get_multipart(switch_core_session_t *session, const char *prefix, const char *sdp, char **mp_type)
{
#ifdef SOFIA_ISUP
	void *isup_payload = NULL, *new_isup_payload = NULL;
	size_t isup_len = 0, new_isup_len = 0;
#endif
	private_object_t *tech_pvt = switch_core_session_get_private(session);
	switch_stream_handle_t stream = { 0 };
	switch_event_header_t *hi = NULL;
	int x = 0;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	const char *boundary = switch_core_session_get_uuid(session);

	SWITCH_STANDARD_STREAM(stream);
	if ((hi = switch_channel_variable_first(channel))) {
		for (; hi; hi = hi->next) {
			const char *name = (char *) hi->name;
			char *value = (char *) hi->value;

			if (!strcasecmp(name, prefix)) {
				if (hi->idx > 0) {
					int i = 0;

					for(i = 0; i < hi->idx; i++) {
						process_mp(session, &stream, boundary, hi->array[i]);
						x++;
					}
				} else {
					process_mp(session, &stream, boundary, value);
					x++;
				}
			}
		}
		switch_channel_variable_last(channel);
	}

	if (x) {
		*mp_type = switch_core_session_sprintf(session, "multipart/mixed; boundary=%s", boundary);
#ifdef SOFIA_ISUP
		isup_payload = switch_channel_get_private(channel, SOFIA_ISUP_PAYLOAD_PVT);
		isup_len = (size_t)(unsigned long)switch_channel_get_private(channel, SOFIA_ISUP_PAYLOAD_LEN_PVT);
		if (isup_payload) {
			size_t len, offset;
			msg_t *msg;
			msg_content_type_t *c;
			msg_multipart_t *mp;
			msg_payload_t *pl;
			msg_header_t *h = NULL;
			char *b;
			su_home_t *home;
			new_isup_payload = sofia_media_manipulate_isup_iam(session, channel, isup_payload, isup_len, &new_isup_len);
			msg = msg_create(sip_default_mclass(), 0);
			home = msg_home(msg);
			c = sip_content_type_make(home, *mp_type);
			mp = msg_multipart_create(home, "application/sdp", sdp, strlen(sdp));
			mp->mp_next = msg_multipart_create(home, "application/isup;version=itu-t92+", new_isup_payload, isup_len);
			msg_multipart_complete(home, c, mp);
			h = NULL;
			msg_multipart_serialize(&h, mp);
			len = msg_multipart_prepare(msg, mp, 0);
			pl = sip_payload_create(tech_pvt->nh->nh_home, NULL, len);
			b = pl->pl_data;
			for (offset = 0, h = (msg_header_t *)mp; offset < len; h = h->sh_succ) {
				memcpy(b + offset, h->sh_data, h->sh_len);
				offset += h->sh_len;
			}
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "[isup] Returning multipart/mixed isup payload of len %zd\n", isup_len);
			switch_safe_free(stream.data);
			msg_destroy(msg);
			return pl;
		}
#endif
		if (sdp) {
			stream.write_function(&stream, "--%s\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s\r\n", boundary, strlen(sdp) + 1, sdp);
		}
		stream.write_function(&stream, "--%s--\r\n", boundary);
	}

	if (!zstr((char *) stream.data)) {
		return sip_payload_create(tech_pvt->nh->nh_home, stream.data, strlen(stream.data));
	} else {
		switch_safe_free(stream.data);
		return NULL;
	}
}





/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */

