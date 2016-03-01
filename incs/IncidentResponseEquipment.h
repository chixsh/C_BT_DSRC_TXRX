/*
 * Generated by asn1c-0.9.21 (http://lionet.info/asn1c)
 * From ASN.1 module "ITIS"
 * 	found in "../downloads/DSRC_R36_Source.ASN"
 * 	`asn1c -fcompound-names`
 */

#ifndef    _IncidentResponseEquipment_H_
#define    _IncidentResponseEquipment_H_


#include <asn_application.h>

/* Including external dependencies */
#include <ENUMERATED.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum IncidentResponseEquipment {
    IncidentResponseEquipment_ground_fire_suppression = 9985,
    IncidentResponseEquipment_heavy_ground_equipment = 9986,
    IncidentResponseEquipment_aircraft = 9988,
    IncidentResponseEquipment_marine_equipment = 9989,
    IncidentResponseEquipment_support_equipment = 9990,
    IncidentResponseEquipment_medical_rescue_unit = 9991,
    IncidentResponseEquipment_other = 9993,
    IncidentResponseEquipment_ground_fire_suppression_other = 9994,
    IncidentResponseEquipment_engine = 9995,
    IncidentResponseEquipment_truck_or_aerial = 9996,
    IncidentResponseEquipment_quint = 9997,
    IncidentResponseEquipment_tanker_pumper_combination = 9998,
    IncidentResponseEquipment_brush_truck = 10000,
    IncidentResponseEquipment_aircraft_rescue_firefighting = 10001,
    IncidentResponseEquipment_heavy_ground_equipment_other = 10004,
    IncidentResponseEquipment_dozer_or_plow = 10005,
    IncidentResponseEquipment_tractor = 10006,
    IncidentResponseEquipment_tanker_or_tender = 10008,
    IncidentResponseEquipment_aircraft_other = 10024,
    IncidentResponseEquipment_aircraft_fixed_wing_tanker = 10025,
    IncidentResponseEquipment_helitanker = 10026,
    IncidentResponseEquipment_helicopter = 10027,
    IncidentResponseEquipment_marine_equipment_other = 10034,
    IncidentResponseEquipment_fire_boat_with_pump = 10035,
    IncidentResponseEquipment_boat_no_pump = 10036,
    IncidentResponseEquipment_support_apparatus_other = 10044,
    IncidentResponseEquipment_breathing_apparatus_support = 10045,
    IncidentResponseEquipment_light_and_air_unit = 10046,
    IncidentResponseEquipment_medical_rescue_unit_other = 10054,
    IncidentResponseEquipment_rescue_unit = 10055,
    IncidentResponseEquipment_urban_search_rescue_unit = 10056,
    IncidentResponseEquipment_high_angle_rescue = 10057,
    IncidentResponseEquipment_crash_fire_rescue = 10058,
    IncidentResponseEquipment_bLS_unit = 10059,
    IncidentResponseEquipment_aLS_unit = 10060,
    IncidentResponseEquipment_mobile_command_post = 10075,
    IncidentResponseEquipment_chief_officer_car = 10076,
    IncidentResponseEquipment_hAZMAT_unit = 10077,
    IncidentResponseEquipment_type_i_hand_crew = 10078,
    IncidentResponseEquipment_type_ii_hand_crew = 10079,
    IncidentResponseEquipment_privately_owned_vehicle = 10083,
    IncidentResponseEquipment_other_apparatus_resource = 10084,
    IncidentResponseEquipment_ambulance = 10085,
    IncidentResponseEquipment_bomb_squad_van = 10086,
    IncidentResponseEquipment_combine_harvester = 10087,
    IncidentResponseEquipment_construction_vehicle = 10088,
    IncidentResponseEquipment_farm_tractor = 10089,
    IncidentResponseEquipment_grass_cutting_machines = 10090,
    IncidentResponseEquipment_hAZMAT_containment_tow = 10091,
    IncidentResponseEquipment_heavy_tow = 10092,
    IncidentResponseEquipment_light_tow = 10094,
    IncidentResponseEquipment_flatbed_tow = 10114,
    IncidentResponseEquipment_hedge_cutting_machines = 10093,
    IncidentResponseEquipment_mobile_crane = 10095,
    IncidentResponseEquipment_refuse_collection_vehicle = 10096,
    IncidentResponseEquipment_resurfacing_vehicle = 10097,
    IncidentResponseEquipment_road_sweeper = 10098,
    IncidentResponseEquipment_roadside_litter_collection_crews = 10099,
    IncidentResponseEquipment_salvage_vehicle = 10100,
    IncidentResponseEquipment_sand_truck = 10101,
    IncidentResponseEquipment_snowplow = 10102,
    IncidentResponseEquipment_steam_roller = 10103,
    IncidentResponseEquipment_swat_team_van = 10104,
    IncidentResponseEquipment_track_laying_vehicle = 10105,
    IncidentResponseEquipment_unknown_vehicle = 10106,
    IncidentResponseEquipment_white_lining_vehicle = 10107,
    IncidentResponseEquipment_dump_truck = 10108,
    IncidentResponseEquipment_supervisor_vehicle = 10109,
    IncidentResponseEquipment_snow_blower = 10110,
    IncidentResponseEquipment_rotary_snow_blower = 10111,
    IncidentResponseEquipment_road_grader = 10112,
    IncidentResponseEquipment_steam_truck = 10113
    /*
     * Enumeration is extensible
     */
} e_IncidentResponseEquipment;

/* IncidentResponseEquipment */
typedef ENUMERATED_t IncidentResponseEquipment_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IncidentResponseEquipment;
asn_struct_free_f IncidentResponseEquipment_free;
asn_struct_print_f IncidentResponseEquipment_print;
asn_constr_check_f IncidentResponseEquipment_constraint;
ber_type_decoder_f IncidentResponseEquipment_decode_ber;
der_type_encoder_f IncidentResponseEquipment_encode_der;
xer_type_decoder_f IncidentResponseEquipment_decode_xer;
xer_type_encoder_f IncidentResponseEquipment_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _IncidentResponseEquipment_H_ */
