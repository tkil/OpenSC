/*
 * pkcs15-sc-hsm.c : PKCS#15 emulation for write support
 *
 * Copyright (C) 2012 Andreas Schwier, CardContact, Minden, Germany
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>

#include "../libopensc/opensc.h"
#include "../libopensc/cardctl.h"
#include "../libopensc/log.h"
#include "../libopensc/pkcs15.h"
#include "../libopensc/cards.h"
#include "../libopensc/card-sc-hsm.h"

#include "pkcs15-init.h"
#include "profile.h"



static int sc_hsm_delete_ef(sc_pkcs15_card_t *p15card, u8 prefix, u8 id)
{
	sc_card_t *card = p15card->card;
	sc_path_t path;
	u8 fid[2];
	int r;

	fid[0] = prefix;
	fid[1] = id;

	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, 2, 0, 0);

	r = sc_delete_file(card, &path);
	LOG_TEST_RET(card->ctx, r, "Could not delete file");

	LOG_FUNC_RETURN(card->ctx, r);
}



static int sc_hsm_update_ef(sc_pkcs15_card_t *p15card, u8 prefix, u8 id, int erase, u8 *buf, size_t buflen)
{
	sc_card_t *card = p15card->card;
	sc_file_t *file = NULL;
	sc_file_t newfile;
	sc_path_t path;
	u8 fid[2];
	int r;

	fid[0] = prefix;
	fid[1] = id;

	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, 2, 0, 0);

	r = sc_select_file(card, &path, NULL);

	if ((r == SC_SUCCESS) && erase) {
		r = sc_delete_file(card, &path);
		LOG_TEST_RET(card->ctx, r, "Could not delete file");
		r = SC_ERROR_FILE_NOT_FOUND;
	}

	if (r == SC_ERROR_FILE_NOT_FOUND) {
		file = sc_file_new();
		file->id = (path.value[0] << 8) | path.value[1];
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		file->size = (size_t) 0;
		file->status = SC_FILE_STATUS_ACTIVATED;
		r = sc_create_file(card, file);
		sc_file_free(file);
		LOG_TEST_RET(card->ctx, r, "Could not creat file");
	}

	r = sc_update_binary(card, 0, buf, buflen, 0);
	LOG_FUNC_RETURN(card->ctx, r);
}



static int sc_hsm_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_pkcs15_object_t *obj)
{
	// Keys are automatically generated in GENERATE ASYMMETRIC KEY PAIR command
	LOG_FUNC_CALLED(p15card->card->ctx);
	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}



static int sc_hsm_generate_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
															struct sc_pkcs15_object *object,
															struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	sc_cardctl_sc_hsm_keygen_info_t sc_hsm_keyinfo;
	struct sc_object_id rsa15withSHA256 = { { 0,4,0,127,0,7,2,2,2,1,2,-1 } };
	sc_cvc_t cvc;
	u8 pubexp[] = { 0x01, 0x00, 0x01 };
	u8 *cvcbin, *cvcpo;
	const u8 *pp;
	unsigned int cla,tag;
	size_t taglen, cvclen;
	int r;

	LOG_FUNC_CALLED(p15card->card->ctx);

	if ((key_info->id.len != 1) || (key_info->id.value[0] == 0)) {
		sc_log(ctx, "Key ID must be one byte and between 1 and 255");
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	memset(&cvc, 0, sizeof(cvc));

	strcpy(cvc.car, "UTCA00000");
	strcpy(cvc.chr, "UTTM00000");

	cvc.coefficientAorExponentlen = sizeof(pubexp);
	cvc.coefficientAorExponent = malloc(sizeof(pubexp));
	if (!cvc.coefficientAorExponent) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	memcpy(cvc.coefficientAorExponent, pubexp, sizeof(pubexp));

	cvc.pukoid = rsa15withSHA256;
	cvc.modulusSize = key_info->modulus_length;

	r = sc_pkcs15emu_sc_hsm_encode_cvc(p15card, &cvc, &cvcbin, &cvclen);
	sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
	LOG_TEST_RET(p15card->card->ctx, r, "Could not encode GAKP cdata");


	cvcpo = cvcbin;
	sc_asn1_read_tag(&cvcpo, cvclen, &cla, &tag, &taglen);
	sc_asn1_read_tag(&cvcpo, cvclen, &cla, &tag, &taglen);

	key_info->key_reference = key_info->id.value[0];
	sc_hsm_keyinfo.key_id = key_info->id.value[0];
	sc_hsm_keyinfo.auth_key_id = 0;
	sc_hsm_keyinfo.gakprequest = cvcpo;
	sc_hsm_keyinfo.gakprequest_len = taglen;

	r = sc_card_ctl(card, SC_CARDCTL_SC_HSM_GENERATE_KEY, &sc_hsm_keyinfo);
	if (r < 0)
		goto out;


	cvcpo = sc_hsm_keyinfo.gakpresponse;
	cvclen = sc_hsm_keyinfo.gakpresponse_len;

	r = sc_pkcs15emu_sc_hsm_decode_cvc(p15card, (const u8 **)&cvcpo, &cvclen, &cvc);
	if (r < 0) {
		sc_log(p15card->card->ctx, "Could not decode GAKP rdata");
		r = SC_ERROR_OBJECT_NOT_VALID;
		goto out;
	}

	if (((key_info->modulus_length + 7) / 8) != cvc.primeOrModuluslen) {
		sc_log(p15card->card->ctx, "Modulus size in request does not match generated public key");
		r = SC_ERROR_OBJECT_NOT_VALID;
		goto out;
	}

	if (pubkey != NULL)   {
		pubkey->algorithm = SC_ALGORITHM_RSA;
		pubkey->u.rsa.modulus.len	= cvc.primeOrModuluslen;
		pubkey->u.rsa.modulus.data	= malloc(pubkey->u.rsa.modulus.len);
		pubkey->u.rsa.exponent.len	= sizeof(pubexp);
		pubkey->u.rsa.exponent.data	= malloc(pubkey->u.rsa.exponent.len);
		if (!pubkey->u.rsa.modulus.data || !pubkey->u.rsa.exponent.data) {
			r = SC_ERROR_OBJECT_NOT_VALID;
			goto out;

		}
		memcpy(pubkey->u.rsa.exponent.data, pubexp, pubkey->u.rsa.exponent.len);
		memcpy(pubkey->u.rsa.modulus.data, cvc.primeOrModulus, pubkey->u.rsa.modulus.len);
	}

	out:

	sc_pkcs15emu_sc_hsm_free_cvc(&cvc);

	if (cvcbin) {
		free(cvcbin);
	}
	if (sc_hsm_keyinfo.gakpresponse) {
		free(sc_hsm_keyinfo.gakpresponse);
	}
	LOG_FUNC_RETURN(p15card->card->ctx, r);
}



static int sc_hsm_emu_store_cert(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data)

{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) object->data;
	struct sc_pkcs15_object *prkey;
	int r;

	r = sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_PRKEY, &cert_info->id , &prkey);

	if (r == SC_ERROR_OBJECT_NOT_FOUND) {
		// ToDo Add to list of other certificates
	} else {
		LOG_TEST_RET(p15card->card->ctx, r, "Error locating matching private key");
		r = sc_hsm_update_ef(p15card, EE_CERTIFICATE_PREFIX, ((struct sc_pkcs15_prkey_info *)prkey->data)->key_reference, 1, data->value, data->len);
	}
	return r;
}



static int sc_hsm_emu_delete_cert(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object)

{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) object->data;
	struct sc_pkcs15_object *prkey;
	int r;

	r = sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_PRKEY, &cert_info->id , &prkey);

	if (r == SC_ERROR_OBJECT_NOT_FOUND) {
		// ToDo Add to list of other certificates
	} else {
		LOG_TEST_RET(p15card->card->ctx, r, "Error locating matching private key");
		r = sc_hsm_delete_ef(p15card, EE_CERTIFICATE_PREFIX, ((struct sc_pkcs15_prkey_info *)prkey->data)->key_reference);
	}
	return r;
}



static int sc_hsm_emu_store_binary(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data)

{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_data_info *data_info = (struct sc_pkcs15_data_info *) object->data;
	sc_path_t path;
	u8 id[2];
	int r;

	id[0] = DATA_PREFIX;
	id[1] = data_info->id.value[0];

	sc_path_set(&path, SC_PATH_TYPE_FILE_ID, id, 2, 0, 0);
	data_info->path = path;

	r = sc_hsm_update_ef(p15card, DATA_PREFIX, data_info->id.value[0], 1, data->value, data->len);
	return r;
}



static int sc_hsm_emu_store_data(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data, struct sc_path *path)

{
	struct sc_context *ctx = p15card->card->ctx;
	int r;

	LOG_FUNC_CALLED(ctx);

	switch (object->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
	case SC_PKCS15_TYPE_PUBKEY:
		r = SC_SUCCESS;
		break;
	case SC_PKCS15_TYPE_CERT:
		r = sc_hsm_emu_store_cert(p15card, profile, object, data);
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		r = sc_hsm_emu_store_binary(p15card, profile, object, data);
		break;
	default:
		r = SC_ERROR_NOT_IMPLEMENTED;
		break;
	}

	LOG_FUNC_RETURN(ctx, r);
}



static int sc_hsm_emu_delete_object(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object, const struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	int r;

	LOG_FUNC_CALLED(ctx);

	switch (object->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
		r = sc_hsm_delete_ef(p15card, KEY_PREFIX, ((struct sc_pkcs15_prkey_info *)object->data)->key_reference);
		break;
	case SC_PKCS15_TYPE_CERT:
		r = sc_hsm_emu_delete_cert(p15card, profile, object);
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		r = sc_delete_file(p15card->card, path);
		break;
	default:
		r = SC_ERROR_NOT_IMPLEMENTED;
		break;
	}

	LOG_FUNC_RETURN(ctx, r);
}



static int sc_hsm_emu_update_prkd(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	u8 *buf;
	size_t buflen;
	int r;

	r = sc_pkcs15_encode_prkdf_entry(p15card->card->ctx, object, &buf, &buflen);
	LOG_TEST_RET(p15card->card->ctx, r, "Error encoding PRKD entry");

	r = sc_hsm_update_ef(p15card, PRKD_PREFIX, key_info->key_reference, 0, buf, buflen);
	free(buf);
	return r;
}



static int sc_hsm_emu_update_dcod(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_data_info *cert_info = (struct sc_pkcs15_data_info *) object->data;
	u8 *buf;
	size_t buflen;
	int r;

	r = sc_pkcs15_encode_dodf_entry(p15card->card->ctx, object, &buf, &buflen);
	LOG_TEST_RET(p15card->card->ctx, r, "Error encoding DCOD entry");

	r = sc_hsm_update_ef(p15card, DCOD_PREFIX, cert_info->id.value[0], 0, buf, buflen);
	free(buf);
	return r;
}



static int sc_hsm_emu_update_any_df(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		unsigned op, struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv = SC_ERROR_NOT_SUPPORTED;

	SC_FUNC_CALLED(ctx, 1);
	switch(op)   {
	case SC_AC_OP_ERASE:
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Update DF; erase object('%s',type:%X)", object->label, object->type);
		switch(object->type & SC_PKCS15_TYPE_CLASS_MASK) {
		case SC_PKCS15_TYPE_PRKEY:
			rv = sc_hsm_delete_ef(p15card, PRKD_PREFIX, ((struct sc_pkcs15_prkey_info *)object->data)->key_reference);
			break;
		case SC_PKCS15_TYPE_CERT:
			rv = SC_SUCCESS;
			break;
		case SC_PKCS15_TYPE_DATA_OBJECT:
			rv = sc_hsm_delete_ef(p15card, DCOD_PREFIX, ((struct sc_pkcs15_data_info *)object->data)->path.value[1]);
			break;
		}
		break;
	case SC_AC_OP_UPDATE:
	case SC_AC_OP_CREATE:
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Update DF; create object('%s',type:%X)", object->label, object->type);
		switch(object->type & SC_PKCS15_TYPE_CLASS_MASK) {
		case SC_PKCS15_TYPE_PUBKEY:
			rv = SC_SUCCESS;
			break;
		case SC_PKCS15_TYPE_PRKEY:
			rv = sc_hsm_emu_update_prkd(profile, p15card, object);
			break;
		case SC_PKCS15_TYPE_CERT:
			rv = SC_SUCCESS;
			break;
		case SC_PKCS15_TYPE_DATA_OBJECT:
			rv = sc_hsm_emu_update_dcod(profile, p15card, object);
			break;
		}
	}
	SC_FUNC_RETURN(ctx, 1, rv);
}



static struct sc_pkcs15init_operations
sc_pkcs15init_sc_hsm_operations = {
	NULL, 						/* erase_card */
	NULL,						/* init_card  */
	NULL,						/* create_dir */
	NULL,						/* create_domain */
	NULL,						/* select_pin_reference */
	NULL,						/* create_pin */
	NULL,						/* select key reference */
	sc_hsm_create_key,
	NULL,						/* store_key */
	sc_hsm_generate_key,
	NULL,						/* encode private key */
	NULL,						/* encode public key */
	NULL,						/* finalize_card */
	sc_hsm_emu_delete_object,	/* delete object */
	NULL,						/* pkcs15init emulation update_dir */
	sc_hsm_emu_update_any_df,	/* pkcs15init emulation update_any_df */
	NULL,						/* pkcs15init emulation update_tokeninfo */
	NULL,						/* pkcs15init emulation write_info */
	sc_hsm_emu_store_data,
	NULL,						/* sanity_check */
};


struct sc_pkcs15init_operations *
sc_pkcs15init_get_sc_hsm_ops(void)
{
	return &sc_pkcs15init_sc_hsm_operations;
}

