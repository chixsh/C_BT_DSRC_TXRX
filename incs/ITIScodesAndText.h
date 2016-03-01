/*
 * Generated by asn1c-0.9.21 (http://lionet.info/asn1c)
 * From ASN.1 module "ITIS"
 * 	found in "../downloads/DSRC_R36_Source.ASN"
 * 	`asn1c -fcompound-names`
 */

#ifndef    _ITIScodesAndText_H_
#define    _ITIScodesAndText_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include "ITIScodes.h"
#include "ITIStext.h"
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum item_PR_it {
    item_PR_NOTHING_it, /* No components present */
            item_PR_itis_it,
    item_PR_text_it
} item_PR_it;

/* ITIScodesAndText */
typedef struct ITIScodesAndText {
    A_SEQUENCE_OF(struct ITIScodesAndText__Member {
                      struct item_it {
                          item_PR_it present;
                          union item_u_it {
                              ITIScodes_t itis;
                              ITIStext_t text;
                          } choice;

                          /* Context for parsing across buffer boundaries */
                          asn_struct_ctx_t _asn_ctx;
                      } item;

                      /* Context for parsing across buffer boundaries */
                      asn_struct_ctx_t _asn_ctx;
                  })

    list;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} ITIScodesAndText_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ITIScodesAndText;

#ifdef __cplusplus
}
#endif

#endif	/* _ITIScodesAndText_H_ */
