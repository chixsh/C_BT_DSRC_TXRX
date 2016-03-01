/*
 * Generated by asn1c-0.9.21 (http://lionet.info/asn1c)
 * From ASN.1 module "NTCIP"
 * 	found in "../downloads/DSRC_R36_Source.ASN"
 * 	`asn1c -fcompound-names`
 */

#ifndef    _EssPrecipSituation_H_
#define    _EssPrecipSituation_H_


#include <asn_application.h>

/* Including external dependencies */
#include <ENUMERATED.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum EssPrecipSituation {
    EssPrecipSituation_other = 1,
    EssPrecipSituation_unknown = 2,
    EssPrecipSituation_noPrecipitation = 3,
    EssPrecipSituation_unidentifiedSlight = 4,
    EssPrecipSituation_unidentifiedModerate = 5,
    EssPrecipSituation_unidentifiedHeavy = 6,
    EssPrecipSituation_snowSlight = 7,
    EssPrecipSituation_snowModerate = 8,
    EssPrecipSituation_snowHeavy = 9,
    EssPrecipSituation_rainSlight = 10,
    EssPrecipSituation_rainModerate = 11,
    EssPrecipSituation_rainHeavy = 12,
    EssPrecipSituation_frozenPrecipitationSlight = 13,
    EssPrecipSituation_frozenPrecipitationModerate = 14,
    EssPrecipSituation_frozenPrecipitationHeavy = 15
} e_EssPrecipSituation;

/* EssPrecipSituation */
typedef ENUMERATED_t EssPrecipSituation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_EssPrecipSituation;
asn_struct_free_f EssPrecipSituation_free;
asn_struct_print_f EssPrecipSituation_print;
asn_constr_check_f EssPrecipSituation_constraint;
ber_type_decoder_f EssPrecipSituation_decode_ber;
der_type_encoder_f EssPrecipSituation_encode_der;
xer_type_decoder_f EssPrecipSituation_decode_xer;
xer_type_encoder_f EssPrecipSituation_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _EssPrecipSituation_H_ */
