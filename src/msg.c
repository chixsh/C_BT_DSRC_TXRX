/***************************************************************************
 * 1. INCLUDES                                                             *
 ***************************************************************************/
#include "genericAPI.h"

/********************************************************************************
 * Create AsmMsg_Sign request.                                                  *
 * The message structure is shown in the interface document (see Section 4.5.1.)*
 ********************************************************************************/
#define BIGENDIAN               \
( {                             \
        long x = 0x00000001;    \
        !(*(char *)(&x));       \
})
#define swap32_(x)       ((((x)&0xFF)<<24)       \
                         |(((x)>>24)&0xFF)       \
                         |(((x)&0x0000FF00)<<8)  \
                         |(((x)&0x00FF0000)>>8)  )

void
msg_create_sign_msg(
        UINT8 *buff,
        UINT8 *app_data,
        int *buffSize,
        int app_length,
        UINT8 CertificateType, unsigned int *psid, int psidLen, UINT8 generationLocation, long generation_latitude,
        long generation_longitude) {
    // data to be signed
    // UINT8 apl_data[] = {0,1,2,3,4,5,6,7,8,9}; // for testing purposes only
    // request structures
    AsmMsg_Sign_Msg_Req1_t *req1 = 0;
    AsmMsg_Sign_Msg_Req2_t *req2 = 0;
    AsmMsg_Sign_Msg_Req3_t *req3 = 0;
    // calcuate size
    *buffSize = sizeof(AsmMsg_Sign_Msg_Req1_t)
                - sizeof(req1->application_data)
                // + sizeof(apl_data)
                + app_length
                + psidLen//sizeof(AsmMsg_Sign_Msg_Req2_t)
                + sizeof(AsmMsg_Sign_Msg_Req3_t);

    //construct AsmMsg_Sign_Msg_Req1_t
    req1 = (AsmMsg_Sign_Msg_Req1_t *) buff;
    req1->command = CMD_SIGN_POST;
    req1->handle = gen_htonl(1); // for testing purposes only
    req1->actual_time = htonll(gen_getcurrentTime());
    req1->signed_message_type = CONTENT_TYPE_SIGNED;
    req1->application_data_length = gen_htonl(app_length);
    gen_memcpy(req1->application_data, app_data, app_length);

    //construct AsmMsg_Sign_Msg_Req2_t + AsmMsg_Sign_Msg_Req3_t
    req2 = (AsmMsg_Sign_Msg_Req2_t * ) &
           buff[*buffSize - psidLen/*sizeof(AsmMsg_Sign_Msg_Req2_t)*/ - sizeof(AsmMsg_Sign_Msg_Req3_t)];
    req3 = (AsmMsg_Sign_Msg_Req3_t * ) & buff[*buffSize - sizeof(AsmMsg_Sign_Msg_Req3_t)];
/*#ifdef USE_LCM
    req2->psid[0] = 0x12; // for testing purposes only
#else
    req2->psid[0] = 0x01; // for testing purposes only
#endif*/
    gen_memcpy(req2->psid, psid, psidLen);
    req3->use_expiry_time = FALSE;
    req3->use_generation_location = generationLocation;
    req3->use_generation_time = TRUE;
    req3->expiry_time = htonll(gen_getcurrentTime() + 1000000); //value is 1 second into the future
    req3->generation_location_latitude = gen_htonl(generation_latitude);
    req3->generation_location_longitude = gen_htonl(generation_longitude);
    req3->generation_location_elevation[0] = 0; // for testing purposes only
    req3->generation_location_elevation[1] = 1; // for testing purposes only
    req3->signer_identifier_type = CertificateType;
    if (CertificateType == 2) //SIGNER_INTERFACE_TYPE_CERT_CHAIN
        req3->signer_identifier_cert_chain_length = -1;
    else
        req3->signer_identifier_cert_chain_length = 0; // whole certificate chain.
    req3->sign_with_fast_verification = 1;

}

void
msg_extract_Sign_OTA(UINT8 *data, UINT8 *signdata, int *recv_size) {
    AsmMsg_Sign_Msg_Res_t *res = 0;
    res = (AsmMsg_Sign_Msg_Res_t *) signdata;
    gen_memcpy(data, res->signed_message_data, gen_ntohl(res->signed_message_length));
    *recv_size = gen_htonl(res->signed_message_length);
}

void
msg_extract_Enc_OTA(UINT8 *data, UINT8 *encdata, int *recv_size) {
    AsmMsg_Enc_Msg_Res1_t *res = 0;
    res = (AsmMsg_Enc_Msg_Res1_t *) encdata;
    gen_memcpy(data, res->encrypted_message_data, gen_ntohl(res->encrypted_message_length));
    *recv_size = gen_htonl(res->encrypted_message_length);
}

void
msg_extract_Wsa_OTA(UINT8 *data, UINT8 *wsadata, UINT16 *recv_size) {
    AsmMsg_Sign_WSA_Res_t *res = 0;
    res = (AsmMsg_Sign_WSA_Res_t *) wsadata;
    gen_memcpy(data, res->signed_wsa_with_chain_data, gen_ntohl(res->signed_wsa_with_chain_length));
    *recv_size = gen_ntohl(res->signed_wsa_with_chain_length);
}

void
msg_create_Wsa_OTA(UINT8 *data, UINT8 *recvdata, int datalength) {
    AsmMsg_Sign_WSA_Res_t *res = 0;
    res = (AsmMsg_Sign_WSA_Res_t *) data;
    res->command = CMD_SIGN_WSA_POST;
    res->handle = gen_htonl(5); // for testing purposes only
    res->signed_wsa_with_chain_length = gen_htonl(datalength);
    gen_memcpy(res->signed_wsa_with_chain_data, recvdata, (datalength));
}

void
msg_extract_Wsa_Verify_OTA(UINT8 *data, UINT8 *verifydata, UINT16 *wsalength) {
    AsmMsg_Verify_WSA_Res1_t *res = 0;
    AsmMsg_Unsigned_Wsa *unsignwsa = 0;
    res = (AsmMsg_Verify_WSA_Res1_t *) verifydata;
    unsignwsa = (AsmMsg_Unsigned_Wsa * )(res->unsigned_wsa_data);
    gen_memcpy(data, unsignwsa->unsigned_data, gen_ntohl(unsignwsa->unsigned_datalength));
    *wsalength = gen_ntohl(unsignwsa->unsigned_datalength);
}

void
msg_create_Sign_OTA(UINT8 *data, UINT8 *recvdata, int *recv_size, int datalength) {
    AsmMsg_Sign_Msg_Res_t *res = 0;
    res = (AsmMsg_Sign_Msg_Res_t *) data;
    res->command = CMD_OK_SIGN_POST;
    res->handle = gen_htonl(1); // for testing purposes only
    res->signed_message_length = gen_htonl(datalength);
    gen_memcpy(res->signed_message_data, recvdata, datalength);
    *recv_size = datalength + 9;
}

void
msg_create_Enc_OTA(UINT8 *data, UINT8 *recvdata, int *recv_size, int datalength) {
    AsmMsg_Enc_Msg_Res1_t *res = 0;
    res = (AsmMsg_Enc_Msg_Res1_t *) data;
    res->command = CMD_ENC_POST;
    res->handle = gen_htonl(3); // for testing purposes only
    res->encrypted_message_length = gen_htonl(datalength);
    gen_memcpy(res->encrypted_message_data, recvdata, datalength);
    *recv_size = datalength + 9;
}

void
msg_decode_certificate(UINT8 *signdata, UINT8 *Algo, UINT16 *certlength) {
    AsmMsg_Extraction_Signed_Msg1 *res1 = 0;
    Asm_certificate *cert = 0;
    UINT8 certificate_flength = 0, certificate_sublength = 0, certificate_perlength = 0, certificate_klength = 0;
    UINT8 *intpo;

    cert = (Asm_certificate * ) & signdata[sizeof(AsmMsg_Extraction_Signed_Msg1) - sizeof(res1->cert_type)];
    intpo = (UINT8 * ) & signdata[sizeof(AsmMsg_Extraction_Signed_Msg1) - sizeof(res1->cert_type)];

    certificate_flength = sizeof(cert->CertVersion) + sizeof(cert->SubType) + sizeof(cert->SignerId);

    certificate_sublength = sizeof(cert->scope_ntlocalized.sname) + cert->scope_ntlocalized.sname.length_subject_name -
                            sizeof(cert->scope_ntlocalized.sname.subj_name[0]);

    certificate_perlength = *(intpo + certificate_flength + certificate_sublength +
                              sizeof(cert->scope_ntlocalized.type));

    certificate_klength = *(intpo + certificate_flength + certificate_sublength + certificate_perlength +
                            sizeof(cert->scope_ntlocalized.type) +
                            sizeof(cert->scope_ntlocalized.length_permission_field) + sizeof(cert->Expiration) +
                            sizeof(cert->crl_series));

    *certlength = sizeof(Asm_certificate) - sizeof(cert->scope_ntlocalized.sname) + certificate_sublength -
                  sizeof(cert->key) + certificate_klength;
    *Algo = *(intpo + certificate_flength + certificate_sublength + certificate_perlength +
              sizeof(cert->scope_ntlocalized.type) + sizeof(cert->scope_ntlocalized.length_permission_field) +
              sizeof(cert->Expiration) + sizeof(cert->crl_series) + sizeof(cert->length_public_key));
}

void
msg_decode_sign_msg(UINT8 *app_data, UINT8 *signdata, int *recv_size, UINT8 *Algo, int send_size) {
    AsmMsg_Extraction_Signed_Msg1 *res1 = 0;
    AsmMsg_Extraction_Signed_Msg2 *res2 = 0;
    AsmMsg_Extraction_Signed_Msg3 *res3 = 0;
    AsmMsg_Extraction_Signed_Msg4 *res4 = 0;
    UINT16 certlength = 0, buflength = 0;
    UINT8 mfpresense = 0, certtype = 0;

    // Extracting the AsmMsg_Extraction_Signed_Msg1    
    res1 = (AsmMsg_Extraction_Signed_Msg1 *) signdata;
    buflength = sizeof(AsmMsg_Extraction_Signed_Msg1);

    // Checking the certificate type. if it is cert chain, caluculating the length, Extracting the AsmMsg_Extraction_Signed_Msg2
    // cert Type is SIGNER_TYPE_CERT_CHAIN
    if (res1->CertType == SIGNER_TYPE_CERT_CHAIN) {
        certtype = SIGNER_TYPE_CERT_CHAIN;
        msg_decode_certificate(signdata, Algo, &certlength);
        certlength = (res1->cert_type.ctchain.ctlength[0] << 8) | (res1->cert_type.ctchain.ctlength[1]);
        res2 = (AsmMsg_Extraction_Signed_Msg2 * ) &
               signdata[sizeof(AsmMsg_Extraction_Signed_Msg1) + certlength - sizeof(res1->cert_type.ctchain.ct[0])];
    }
        // cert Type is SIGNER_TYPE_CERT_DIGEST_224
    else if (res1->CertType == SIGNER_TYPE_CERT_DIGEST_224) {
        certtype = SIGNER_TYPE_CERT_DIGEST_224;
        certlength = 8;
        res2 = (AsmMsg_Extraction_Signed_Msg2 * ) &
               signdata[sizeof(AsmMsg_Extraction_Signed_Msg1) + certlength - sizeof(res1->cert_type)];
    }
        //cert Type is SIGNER_TYPE_CERT
    else if (res1->CertType == SIGNER_TYPE_CERT) {
        certtype = SIGNER_TYPE_CERT;
        msg_decode_certificate(signdata, Algo, &certlength);
        res2 = (AsmMsg_Extraction_Signed_Msg2 * ) &
               signdata[sizeof(AsmMsg_Extraction_Signed_Msg1) + certlength - sizeof(res1->cert_type)];
    }

    buflength += (certlength - sizeof(res1->cert_type));

    // Checking for mf, based on mf length Extracting the AsmMsg_Extraction_Signed_Msg3
    if (res2->mflength) {
        mfpresense = 1;
        if (certtype == SIGNER_TYPE_CERT_CHAIN)
            res3 = (AsmMsg_Extraction_Signed_Msg3 * ) &
                   signdata[sizeof(AsmMsg_Extraction_Signed_Msg1) + certlength - sizeof(res1->cert_type.ctchain.ct[0]) +
                            sizeof(AsmMsg_Extraction_Signed_Msg2)];
        else
            res3 = (AsmMsg_Extraction_Signed_Msg3 * ) &
                   signdata[sizeof(AsmMsg_Extraction_Signed_Msg1) + certlength - sizeof(res1->cert_type) +
                            sizeof(AsmMsg_Extraction_Signed_Msg2)];
        buflength += sizeof(AsmMsg_Extraction_Signed_Msg2);
    } else {
        mfpresense = 0;
        if (certtype == SIGNER_TYPE_CERT_CHAIN)
            res3 = (AsmMsg_Extraction_Signed_Msg3 * ) &
                   signdata[sizeof(AsmMsg_Extraction_Signed_Msg1) + certlength - sizeof(res1->cert_type.ctchain.ct[0]) +
                            sizeof(AsmMsg_Extraction_Signed_Msg2) - 1];
        else
            res3 = (AsmMsg_Extraction_Signed_Msg3 * ) &
                   signdata[sizeof(AsmMsg_Extraction_Signed_Msg1) + certlength - sizeof(res1->cert_type) +
                            sizeof(AsmMsg_Extraction_Signed_Msg2) - 1];
        buflength += (sizeof(AsmMsg_Extraction_Signed_Msg2) - 1);
    }

    // Caluculating the application data length and extracting the app data
    *recv_size = ((res3->app_length[0] << 24) | (res3->app_length[1] << 16) | (res3->app_length[2] << 8) |
                  (res3->app_length[3]));
    gen_memcpy(app_data, res3->app_data, *recv_size);

    buflength += (sizeof(AsmMsg_Extraction_Signed_Msg3) + *recv_size - sizeof(res3->app_data[0]));

    // Extracting the AsmMsg_Extraction_Signed_Msg4 to check the Alogoritham used for Signing    
    if (certtype == SIGNER_TYPE_CERT_CHAIN) {
        if (mfpresense)
            res4 = (AsmMsg_Extraction_Signed_Msg4 * ) &
                   signdata[sizeof(AsmMsg_Extraction_Signed_Msg1) + certlength - sizeof(res1->cert_type.ctchain.ct[0]) +
                            sizeof(AsmMsg_Extraction_Signed_Msg2) + sizeof(AsmMsg_Extraction_Signed_Msg3) -
                            sizeof(res3->app_data[0]) + *recv_size];
        else
            res4 = (AsmMsg_Extraction_Signed_Msg4 * ) &
                   signdata[sizeof(AsmMsg_Extraction_Signed_Msg1) + certlength - sizeof(res1->cert_type.ctchain.ct[0]) +
                            sizeof(AsmMsg_Extraction_Signed_Msg2) - 1 + sizeof(AsmMsg_Extraction_Signed_Msg3) -
                            sizeof(res3->app_data[0]) + *recv_size];
    } else {
        if (mfpresense)
            res4 = (AsmMsg_Extraction_Signed_Msg4 * ) &
                   signdata[sizeof(AsmMsg_Extraction_Signed_Msg1) + certlength - sizeof(res1->cert_type) +
                            sizeof(AsmMsg_Extraction_Signed_Msg2) + sizeof(AsmMsg_Extraction_Signed_Msg3) -
                            sizeof(res3->app_data[0]) + *recv_size];
        else
            res4 = (AsmMsg_Extraction_Signed_Msg4 * ) &
                   signdata[sizeof(AsmMsg_Extraction_Signed_Msg1) + certlength - sizeof(res1->cert_type) +
                            sizeof(AsmMsg_Extraction_Signed_Msg2) - 1 + sizeof(AsmMsg_Extraction_Signed_Msg3) -
                            sizeof(res3->app_data[0]) + *recv_size];
    }

    if (mfpresense)
        buflength += (sizeof(AsmMsg_Extraction_Signed_Msg4) - sizeof(res4->sign));

    if ((certtype == SIGNER_TYPE_CERT_DIGEST_224)) {
        if ((send_size - buflength) > 2 * SIZE_OF_ECC224_PUP_KEY)
            *Algo = ECDSA_256;
        else
            *Algo = ECDSA_224;
    }
}

/********************************************************************************
 * Create AsmMsg_Verify request.                                                *
 * The message structure is shown in the interface document (see Section 4.6.1.)*
 ********************************************************************************/
void
msg_create_verify_msg(
        const UINT8 *signBuff,
        UINT8 *buff,
        int *buffSize, UINT32 msgValidityDistance, UINT8 detectReplay, UINT8 generationLocationValidity,
        long local_latitude, long local_longitude) {
    // request structures
    AsmMsg_Verify_Msg_Req1_t *req1 = 0;
    AsmMsg_Verify_Msg_Req2_t *req2 = 0;

    //use response of sign request as input -> loopback
    const AsmMsg_Sign_Msg_Res_t *res = 0;
    res = (const AsmMsg_Sign_Msg_Res_t *) signBuff;

    //calcualte size
    *buffSize = sizeof(AsmMsg_Verify_Msg_Req1_t)
                - sizeof(res->signed_message_data[0])
                + gen_ntohl(res->signed_message_length)
                + sizeof(AsmMsg_Verify_Msg_Req2_t);

    // construct AsmMsg_Verify_Msg_Req1_t
    req1 = (AsmMsg_Verify_Msg_Req1_t *) buff;
    req1->command = CMD_VERIFY_POST;
    req1->handle = gen_htonl(2); // for testing purposes only
    req1->actual_time = htonll(gen_getcurrentTime());
    req1->signed_message_length = res->signed_message_length;
    gen_memcpy(req1->signed_message_data, res->signed_message_data, gen_htonl(res->signed_message_length));

    // construct AsmMsg_Verify_Msg_Req2_t
    req2 = (AsmMsg_Verify_Msg_Req2_t * ) & buff[*buffSize - sizeof(AsmMsg_Verify_Msg_Req2_t)];
    req2->perform_cryptographic_verification = TRUE;
    req2->detect_replay = detectReplay;
    req2->require_generation_time = TRUE;
    req2->message_validity_period = htonll(5000000); // 5 second
    req2->generation_time.time = 0; // This field is not evaluated.
    req2->generation_time_confidence_multiplier = gen_htonl(1000); // 1.0
    req2->use_expiry_time = FALSE;
    req2->expiry_time = 0; // This field is not evaluated.
    req2->require_generation_location = generationLocationValidity;
    req2->message_validity_distance = gen_htonl(msgValidityDistance); // Configurable in km
    req2->generation_location.latitude = gen_htonl(LATITUDE_NOT_AVAILABLE); // This field is not evaluated.
    req2->generation_location.longitude = gen_htonl(LONGITUDE_NOT_AVAILABLE);
    //req2->generation_location_horizontal_confidence_multiplier = gen_htonl(1000); // 1.0
    /* req2->generation_location_elevation_confidence_multiplier This field is never evaluated.*/
    req2->local_location_latitude = gen_htonl(local_latitude);
    req2->local_location_longitude = gen_htonl(local_longitude);
    req2->overdue_CRL_tolerance = 0; // Don't use the overdue CRL tolerance.
}

/*******************************************************************************
 * Create AsmMsg_Enc request.                                                   *
 * The message structure is shown in the interface document (see Section 4.7.1.)*
 ********************************************************************************/
void
msg_create_enc_msg(
        UINT8 *buff,
        UINT8 *app_data,
        int *buffSize,
        int app_length) {
    // request strutures
    AsmMsg_Enc_Req1_t *req1 = 0;
    AsmMsg_Enc_Req2_t *req2 = 0;
    int req1_len = 0;

    // certificate of receiver
    int cert_size = 0;
    UINT8 cert_buff[1024];

    // read certifcate file
    cert_size = gen_readfile("/tmp/keys/root_ca.cert", cert_buff, sizeof(cert_buff));

    // calculate whole message size.
    req1_len = sizeof(AsmMsg_Enc_Req1_t)
               - sizeof(req1->application_data)
               + app_length;

    *buffSize = req1_len
                + sizeof(AsmMsg_Enc_Req2_t)
                - sizeof(req2->recipient_certs)
                + cert_size;

    // construct AsmMsg_Enc_Req1_t
    req1 = (AsmMsg_Enc_Req1_t *) buff;
    req1->command = CMD_ENC_POST;
    req1->handle = gen_htonl(3); // for testing purposes only
    req1->actual_time = htonll(gen_getcurrentTime());
    req1->application_data_length = gen_htonl(app_length);
    req1->application_data_type = CONTENT_TYPE_UNSECURED;  // unsecured
    gen_memcpy(req1->application_data, app_data, app_length);

    // construct AsmMsg_Enc_Req2_t
    req2 = (AsmMsg_Enc_Req2_t * ) & buff[req1_len];
    req2->recipient_number = gen_htons(1);
    gen_memcpy(req2->recipient_certs, cert_buff, cert_size);
}

/********************************************************************************
 * Create AsmMsg_Dec request.                                                   *
 * The message structure is shown in the interface document (see Section 4.8.1.)*
 ********************************************************************************/
void
msg_create_dec_msg(
        const UINT8 *encBuff,
        UINT8 *buff,
        int *buffSize) {
    // request structures
    AsmMsg_Dec_Msg_Req1_t *req1 = 0;
    AsmMsg_Dec_Msg_Req2_t *req2 = 0;

    //use  encryption request response as input
    const AsmMsg_Enc_Msg_Res1_t *res1 = 0;
    const AsmMsg_Enc_Msg_Res2_t *res2 = 0;
    int incoming_length = 0;

    // parse encrypt response message
    res1 = (const AsmMsg_Enc_Msg_Res1_t *) encBuff;
    incoming_length = sizeof(AsmMsg_Enc_Msg_Res1_t)
                      - sizeof(res1->encrypted_message_data)
                      + gen_ntohl(res1->encrypted_message_length)
                      + sizeof(AsmMsg_Enc_Msg_Res2_t);
    res2 = (const AsmMsg_Enc_Msg_Res2_t *) &(encBuff[incoming_length - sizeof(AsmMsg_Enc_Msg_Res2_t)]);

    //calculate buffer size
    *buffSize = sizeof(AsmMsg_Dec_Msg_Req1_t)
                - sizeof(req1->encrypted_message_data)
                + gen_ntohl(res1->encrypted_message_length)
                + sizeof(AsmMsg_Dec_Msg_Req2_t);

    // construct AsmMsg_Dec_Msg_Req1_t
    req1 = (AsmMsg_Dec_Msg_Req1_t *) buff;
    req1->command = CMD_DEC_POST;
    req1->handle = gen_htonl(4); // for testing purposes only
    req1->actual_time = htonll(gen_getcurrentTime());
    req1->encrypted_message_length = res1->encrypted_message_length;
    gen_memcpy(req1->encrypted_message_data, res1->encrypted_message_data, gen_ntohl(res1->encrypted_message_length));

    // construct AsmMsg_Dec_Msg_Req2_t
    req2 = (AsmMsg_Dec_Msg_Req2_t * ) & (buff[*buffSize - sizeof(AsmMsg_Dec_Msg_Req2_t)]);
    req2->allow_no_longer_valid_cert = FALSE;
}

void
msg_decode_dec_msg(
        UINT8 *app_data,
        UINT8 *decBuff,
        int *buffSize) {

    const AsmMsg_Dec_Msg_Res_t *res1 = 0;
    res1 = (const AsmMsg_Dec_Msg_Res_t *) decBuff;
    gen_memcpy(app_data, res1->application_data, gen_ntohl(res1->application_data_length));
    *buffSize = gen_ntohl(res1->application_data_length);
}

/********************************************************************************
 * Create AsmMsg_Sign_WSA request.                                              *
 * The message structure is shown in the interface document (see Section 4.9.1.)*
 ********************************************************************************/
void
msg_create_sign_wsa(UINT8 *buff,
                    UINT8 *wsadata,
                    UINT16 *buffSize,
                    UINT16 wsalength, UINT32 *wsa_config, UINT32 latitude, UINT32 longitude, UINT16 elevation) {
    // request structures
    AsmMsg_Sign_WSA_Req1_t *req1 = 0;
    AsmMsg_Sign_WSA_Req2_t *req2 = 0;
    int i = 0, j = 2, k = 2;
    unsigned int psId = 0;
    unsigned int psidle = 0;
    unsigned int psidex = 0;
    int psidLen = 0, psidLength = 0;
    int len = 0;
    UINT8 *elevation_value;

    for (i = 0; i < wsa_config[1]; i++) {
        if (BIGENDIAN) {
            psidle = wsa_config[k];
            psId = swap32_(psidle);
        }
        psId = putPsidbyLen((UINT8 * ) & psId, wsa_config[k], &psidLen);
        psidLength += psidLen;
        k += 2;
        if (wsa_config[k] == 3) {
            k += 4;
            psidLength += 5;
        }
        else if (wsa_config[k] == 2) {
            k += 3;
            psidLength += 4;
        }
        else {
            k += 1;
            psidLength += 2;
        }
    }


    *buffSize = sizeof(AsmMsg_Sign_WSA_Req1_t)
                - sizeof(req1->application_data)
                + wsalength
                + sizeof(AsmMsg_Sign_WSA_Req2_t)
                - sizeof(req2->permissions)
                + psidLength; //sizeof psid_and_priorities

    // construct AsmMsg_Sign_WSA_Req1_t
    req1 = (AsmMsg_Sign_WSA_Req1_t *) buff;
    req1->command = CMD_SIGN_WSA_POST;
    req1->handle = gen_htonl(5); // for testing purposes only
    req1->actual_time = htonll(gen_getcurrentTime());
    req1->application_data_length = gen_htonl(wsalength);
    gen_memcpy(req1->application_data, wsadata, wsalength);

    // construct AsmMsg_Sign_Msg_Req2_t
    req2 = (AsmMsg_Sign_WSA_Req2_t * ) &
           buff[*buffSize - sizeof(AsmMsg_Sign_WSA_Req2_t) - psidLength + sizeof(req2->permissions)];
    req2->lifetime = htonll(60000000); //value is 60 second into the future
    req2->generation_location_latitude = gen_htonl(latitude);
    req2->generation_location_longitude = gen_htonl(longitude);
    elevation_value = (UINT8 * ) & elevation;
    req2->generation_location_elevation[0] = *elevation_value;
    req2->generation_location_elevation[1] = *(elevation_value + 1);
    req2->sign_with_fast_verification = 1;
    req2->number_of_permissions = gen_htons(wsa_config[1]);
    for (i = 0; i < wsa_config[1]; i++) {
        if (BIGENDIAN)
            psId = swap32_(wsa_config[j]);
        psId = putPsidbyLen((UINT8 * ) & psId, wsa_config[j], &psidLen);
        gen_memcpy(req2->permissions + len, &psId, psidLen);
        len += psidLen;
        req2->permissions[len] = wsa_config[j + 1];
        j += 2;
        len += 1;
        if (wsa_config[j] == 3) {
            req2->permissions[len] = 0x03;
            req2->permissions[len + 1] = wsa_config[j + 1];
            req2->permissions[len + 2] = wsa_config[j + 2];
            req2->permissions[len + 3] = wsa_config[j + 3];
            len += 4;
            j += 4;
        }
        else if (wsa_config[j] == 2) {
            req2->permissions[len] = 0x02;
            req2->permissions[len + 1] = wsa_config[j + 1];
            req2->permissions[len + 2] = wsa_config[j + 2];
            len += 3;
            j += 3;
        }
        else {
            req2->permissions[len] = 0x00;
            len += 1;
            j += 1;
        }
    }
}

/********************************************************************************
 * Create AsmMsg_Verify_WSA request.                                              *
 * The message structure is shown in the interface document (see Section 4.10.1.)*
 ********************************************************************************/
void
msg_create_verify_wsa(
        UINT8 *signBuff,
        UINT8 *buff,
        UINT16 *buffSize, UINT32 *wsa_config, UINT32 latitude, UINT32 longitude) {
    // request structures
    AsmMsg_Verify_WSA_Req1_t *req1 = 0;
    AsmMsg_Verify_WSA_Req2_t *req2 = 0;
    int i = 0, j = 2, k = 2;
    unsigned int psId = 0;
    unsigned int psidle = 0;
    unsigned int psidex = 0;
    int len = 0, psidLen = 0, psidLength = 0;



    //use response of sign request as input -> loopback
    const AsmMsg_Sign_WSA_Res_t *res = 0;
    res = (const AsmMsg_Sign_WSA_Res_t *) signBuff;
    for (i = 0; i < wsa_config[1]; i++) {
        if (BIGENDIAN) {
            psidle = wsa_config[k];
            psId = swap32_(psidle);
        }
        psId = putPsidbyLen((UINT8 * ) & psId, wsa_config[k], &psidLen);
        psidLength += psidLen;
        k += 2;
        if (wsa_config[k] == 3) {
            k += 4;
            psidLength += 5;
        }
        else if (wsa_config[k] == 2) {
            k += 3;
            psidLength += 4;
        }
        else {
            k += 1;
            psidLength += 2;
        }
    }


    // calculate size
    *buffSize = sizeof(AsmMsg_Verify_WSA_Req1_t)
                - sizeof(req1->signed_wsa_data)
                + gen_ntohl(res->signed_wsa_with_chain_length)
                + sizeof(AsmMsg_Verify_WSA_Req2_t)
                - sizeof(req2->permissions)
                + psidLength; //sizeof permissions;

    // construct AsmMsg_Verify_WSA_Req1_t
    req1 = (AsmMsg_Verify_WSA_Req1_t *) buff;
    req1->command = CMD_VERIFY_WSA_POST;
    req1->handle = gen_htonl(6); // for testing purposes only
    req1->actual_time = htonll(gen_getcurrentTime());
    req1->signed_wsa_length = res->signed_wsa_with_chain_length;
    gen_memcpy(req1->signed_wsa_data, res->signed_wsa_with_chain_data, gen_ntohl(res->signed_wsa_with_chain_length));

    // construct AsmMsg_Verify_WSA_Req2_t
    req2 = (AsmMsg_Verify_WSA_Req2_t * ) &
           buff[*buffSize - sizeof(AsmMsg_Verify_WSA_Req2_t) - psidLength + sizeof(req2->permissions)];
    req2->perform_cryptographic_verification = TRUE;
    req2->detect_replay = FALSE;
    req2->use_message_validity_period = TRUE;
    req2->message_validity_period = htonll(60000000);
    req2->generation_time_confidence_multiplier = 0;
    req2->use_message_validity_distance = TRUE;
    req2->message_validity_distance = gen_htonl(200);    // 0 m
    req2->local_location_latitude = gen_htonl(latitude);
    req2->local_location_longitude = gen_htonl(longitude);
    req2->overdue_CRL_tolerance = 0;
    req2->perform_permissions_check = TRUE;
    req2->number_of_permissions = gen_htons(wsa_config[1]);
    for (i = 0; i < wsa_config[1]; i++) {
        if (BIGENDIAN)
            psId = swap32_(wsa_config[j]);
        psId = putPsidbyLen((UINT8 * ) & psId, wsa_config[j], &psidLen);
        gen_memcpy(req2->permissions + len, &psId, psidLen);
        len += psidLen;
        req2->permissions[len] = wsa_config[j + 1];
        j += 2;
        len += 1;
        if (wsa_config[j] == 3) {
            req2->permissions[len] = 0x03;
            req2->permissions[len + 1] = wsa_config[j + 1];
            req2->permissions[len + 2] = wsa_config[j + 2];
            req2->permissions[len + 3] = wsa_config[j + 3];
            len += 4;
            j += 4;
        }
        else if (wsa_config[j] == 2) {
            req2->permissions[len] = 0x02;
            req2->permissions[len + 1] = wsa_config[j + 1];
            req2->permissions[len + 2] = wsa_config[j + 2];
            len += 3;
            j += 3;
        }
        else {
            req2->permissions[len] = 0x00;
            len += 1;
            j += 1;
        }
    }
}

/*********************************************************************************
 * Create AsmMsg_CRL request.                                             *
 * The message structure is shown in the interface document (see Section 4.11.1.)*
 ********************************************************************************/
void
msg_create_crl(
        UINT8 *buff,
        int *buffSize) {
    // request structure
    AsmMsg_CRL_Req_t *req = 0;

    // CRL data
    UINT8 crl[2000];
    int crl_size = 0;

    // read CRL
    /**
     * Note:
     * If you want to send a message with certificate digest, you should read
     * data from the 'crl_digest.dat' file instead of the
     * 'crl_cert.dat' file.
     * If you want to send a message with certificate chain, you should read
     * data from the 'crl_chain.dat' file instead of the
     * 'crl_cert.dat' file.
     */
    crl_size = gen_readfile("crl_cert.dat", crl, sizeof(crl));

    // calculate size
    *buffSize = sizeof(AsmMsg_CRL_Req_t)
                - sizeof(req->crl_data)
                + crl_size;

    // construct AsmMsg_CRL_Req_t
    req = (AsmMsg_CRL_Req_t *) buff;
    req->command = CMD_CRL_POST;
    req->handle = gen_htonl(7); // for testing purposes only
    req->actual_time = htonll(gen_getcurrentTime());
    req->crl_length = gen_htonl(crl_size);
    gen_memcpy(req->crl_data, crl, crl_size);
}

/*********************************************************************************
 * Create AsmMsg_CertChg request.                                                *
 * The message structure is shown in the interface document (see Section 4.12.1.)*
 ********************************************************************************/
void
msg_create_cert_change(
        UINT8 *buff,
        int *buffSize) {
    // request structure
    AsmMsg_CertChg_Req_t *req;

    // calculate size
    *buffSize = sizeof(AsmMsg_CertChg_Req_t);

    // construct AsmMsg_CertChg_Req_t
    req = (AsmMsg_CertChg_Req_t *) buff;
    req->actual_time = htonll(gen_getcurrentTime());
    req->command = CMD_CERT_CHG_POST;
    req->handle = gen_htonl(8); // for testing purposes only
    /* req1->actual_time This field is never evaluated.*/
}

/********************************************************************************
 * Create DataExtractio request.                                                *
 ********************************************************************************/
void
msg_create_extract_data(
        const UINT8 *signBuff,
        UINT8 *buff,
        int *buffSize) {
    // request structures
    AsmMsg_DataExtraction_Req1_t *req1 = 0;


    //use response of sign request as input -> loopback
    const AsmMsg_Sign_Msg_Res_t *res = 0;
    res = (const AsmMsg_Sign_Msg_Res_t *) signBuff;

    //calcualte size
    *buffSize = sizeof(AsmMsg_DataExtraction_Req1_t)
                - sizeof(res->signed_message_data[0])
                + gen_ntohl(res->signed_message_length) + 1;


    // construct AsmMsg_Verify_Msg_Req1_t
    req1 = (AsmMsg_DataExtraction_Req1_t *) buff;
    req1->command = CMD_MSG_DATA_EXT;
    req1->handle = gen_htonl(9); // for testing purposes only
    req1->message_length = res->signed_message_length;
    req1->actual_time = htonll(gen_getcurrentTime());
    gen_memcpy(req1->message_data, res->signed_message_data, gen_ntohl(res->signed_message_length));

}


/********************************************************************************
 * Create Restart request.                                                      *
 ********************************************************************************/
void
msg_create_restart_msg(
        UINT8 *buff,
        int *buffSize) {

    // request structures
    AsmMsg_Restart_Res_t *req1 = 0;

    // calcuate size
    *buffSize = sizeof(AsmMsg_Restart_Res_t);

    //construct AsmMsg_Sign_Msg_Req1_t
    req1 = (AsmMsg_Restart_Res_t *) buff;
    req1->command = CMD_RESTART;
    req1->handle = gen_htonl(10); // for testing purposes only
}

/*********************************************************************************
 * Create AsmMsg_Cert_Info request.                                             *
 * The message structure is shown in the interface document (see Section 4.11.1.)*
 ********************************************************************************/
void
msg_create_cert_info(
        UINT8 *buff,
        int *buffSize) {
    // request structure
    AsmMsg_Cert_Info_Req1_t *req = 0;

    // caluculate Size 
    // CertData data
    UINT8 certdata[2000];
    int certdata_size = 0;

    // read certdata
    certdata_size = gen_readfile("msg_id_nlo_1.cert", certdata, sizeof(certdata));

    // calculate size
    *buffSize = sizeof(AsmMsg_Cert_Info_Req1_t)
                - sizeof(req->identifier)
                + certdata_size;

    // construct AsmMsg_Cert_Info
    req = (AsmMsg_Cert_Info_Req1_t *) buff;
    req->command = CMD_CERT_INFO;
    req->handle = gen_htonl(7); // for testing purposes only
    req->identifier_type = CERTIFICATE;
    req->identifier_length = gen_htonl(certdata_size);
    gen_memcpy(req->identifier, certdata, certdata_size);
}

#ifdef USE_LCM
/*********************************************************************************
 * Create AsmMsg_Cert_Info request.                                             *
 * The message structure is shown in the interface document (see Section 4.11.1.)*
 *********************************************************************************/
void
msg_create_misbehavior_report(
        UINT8* buff,
        int* buffSize,UINT8* report_data,UINT32 report_data_length,long latitude,long longitude,UINT8* elevation)
{
    // request structure
    AsmMsg_Misbehavior_Rep_Msg_Req1_t* req = 0;
    UINT8 *elevation_value;
    
     // calculate size
    *buffSize = sizeof(AsmMsg_Misbehavior_Rep_Msg_Req1_t)
                - sizeof(req->misbehavior_report_data)
                + report_data_length;

    // construct AsmMsg_Cert_Info
    req = (AsmMsg_Misbehavior_Rep_Msg_Req1_t*)buff;
    req->command = CMD_MISBEHAVIOR_REPORT;
    req->handle = gen_htonl(10); // for testing purposes only
    req->actual_time = htonll(gen_getcurrentTime());
    req->type = MISBEHAVIOR_REPORT_CATEGORY_CASUAL_REPORT;
    req->generation_location_latitude = gen_htonl(latitude);
    req->generation_location_longitude = gen_htonl(longitude);
    elevation_value =(UINT8 *)&elevation;
    req->generation_location_elevation[0] = *elevation_value; // for testing purposes only
    req->generation_location_elevation[1] = *(elevation_value+1); // for testing purposes only
    req->misbehavior_report_length = gen_htonl(report_data_length);
    gen_memcpy(req->misbehavior_report_data, report_data, report_data_length);
}
#endif /* USE_LCM */

void encode_length(UINT8 *addr, SINT32 val, SINT32 *retIdx) {
    SINT32 retval = 0;
    UINT8 *p = 0;
    if (!BIGENDIAN)
        retval = swap32_(val); //later should be changed to htobe32()
    else
        retval = val;

    p = (UINT8 * ) & retval;
    if (val <= 0x7F) {
        *retIdx = 1;
        addr[0] = p[3];
    }
    else if (val >= 0x80 && val <= 0x3FFF) {
        *retIdx = 2;
        addr[0] = p[2] | 0x80;
        addr[1] = p[3];
    }
    else if (val >= 0x4000 && val <= 0x1FFFFF) {
        *retIdx = 3;
        addr[0] = p[1] | 0xd0;
        addr[1] = p[2];
        addr[2] = p[3];
    }
    else if (val >= 0x200000 && val <= 0xFFFFFFF) {
        *retIdx = 4;
        addr[0] = p[0] | 0xe0;
        addr[1] = p[1];
        addr[2] = p[2];
        addr[3] = p[3];
    }
}

void
msg_create_misbehavior_report(
        UINT8 *buff,
        int *buffSize, UINT8 *report_data, UINT32 report_data_length, long latitude, long longitude, UINT8 *elevation) {
    SINT32 idx = 0, len = 0;
    UINT8 *elevation_value;
    ThreeDLocation observation_location;
    Time64WithConfidence observation_time;
    buff[idx] = 1; //version
    idx += 1;
    observation_location.latitude = gen_htonl(latitude);
    observation_location.longitude = gen_htonl(longitude);
    gen_memcpy(observation_location.elevation, elevation, 2);
    gen_memcpy((buff + idx), &observation_location, 10);
    idx += 10;
    observation_time.time = htonll(gen_getcurrentTime());
    observation_time.confidence = 0;
    gen_memcpy((buff + idx), &observation_time, 9);
    idx += 9;
    buff[idx] = MISBEHAVIOR_REPORT_CATEGORY_CASUAL_REPORT; // take as argument ??
    idx += 1;
    encode_length(buff + idx, report_data_length, &len); //encode length of misbehaviour report
    gen_memcpy(buff + idx + len, report_data, report_data_length);
    *buffSize = idx + len + report_data_length;

}
