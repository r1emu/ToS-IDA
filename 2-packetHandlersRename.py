#!/usr/bin/python
"""
Tree of Savior IDAPython Script
Packet handlers renaming
"""

import idaapi
import idautils
import idc
from enum import Enum

packetsType = [None] * 10000;
packetsType[3] = "CB_LOGIN" # Size = 65
packetsType[4] = "CB_LOGIN_BY_PASSPORT" # Size = 1052
packetsType[5] = "CB_LOGOUT" # Size = 10
packetsType[9] = "CB_START_GAME" # Size = 13
packetsType[6] = "CB_START_BARRACK" # Size = 11
packetsType[7] = "CB_COMMANDER_CREATE" # Size = 92
packetsType[8] = "CB_COMMANDER_DESTROY" # Size = 11
packetsType[12] = "CB_ECHO" # Size = 30
packetsType[10] = "CB_BARRACKNAME_CHANGE" # Size = 74
packetsType[11] = "CB_COMMANDER_MOVE" # Size = 31
packetsType[13] = "BC_LOGINOK" # Size = 117
packetsType[14] = "BC_LOGOUTOK" # Size = 6
packetsType[18] = "BC_START_GAMEOK" # Size = 33
packetsType[19] = "BC_SINGLE_INFO" # Size = 309
packetsType[15] = "BC_COMMANDER_LIST" # Size = 0
packetsType[16] = "BC_COMMANDER_CREATE" # Size = 318
packetsType[17] = "BC_COMMANDER_DESTROY" # Size = 7
packetsType[20] = "BC_MESSAGE" # Size = 0
packetsType[21] = "BC_ECHO" # Size = 26
packetsType[70] = "CB_IES_MODIFY_INFO" # Size = 0
packetsType[71] = "BC_IES_MODIFY_INFO" # Size = 0
packetsType[72] = "BC_IES_MODIFY_LIST" # Size = 0
packetsType[73] = "CB_IES_REVISION_DELETE" # Size = 0
packetsType[74] = "BC_IES_REVISION_DELETE" # Size = 0
packetsType[22] = "BC_MYPAGE_MAP" # Size = 0
packetsType[23] = "BC_BARRACKNAME_CHANGE" # Size = 75
packetsType[75] = "CB_VISIT" # Size = 74
packetsType[76] = "CB_BUY_THEMA" # Size = 18
packetsType[77] = "BC_ACCOUNT_PROP" # Size = 0
packetsType[78] = "CB_CURRENT_BARRACK" # Size = 39
packetsType[79] = "BC_NORMAL" # Size = 0
packetsType[80] = "CB_POSE" # Size = 15
packetsType[81] = "CB_PLACE_CMD" # Size = 46
packetsType[82] = "CB_CHAT" # Size = 0
packetsType[83] = "BC_CHAT" # Size = 0
packetsType[84] = "CB_ECHO_NORMAL" # Size = 0
packetsType[85] = "CB_JUMP" # Size = 19
packetsType[86] = "BC_JUMP" # Size = 19
packetsType[87] = "BC_SERVER_ENTRY" # Size = 18
packetsType[88] = "CB_PET_PC" # Size = 26
packetsType[89] = "CB_DELETE_PET" # Size = 18
packetsType[90] = "CB_REQ_CHANGE_POSTBOX_STATE" # Size = 22
packetsType[91] = "CB_REQ_GET_POSTBOX_ITEM" # Size = 30
packetsType[92] = "BC_WAIT_QUEUE_ORDER" # Size = 10
packetsType[93] = "CB_CANCEL_SERVER_WAIT_QUEUE" # Size = 10
packetsType[2901] = "CS_LOGIN" # Size = 64
packetsType[2902] = "SC_NORMAL" # Size = 0
packetsType[2903] = "SC_FROM_INTEGRATE" # Size = 0
packetsType[2904] = "CS_REGISTER_SNS_ID" # Size = 16
packetsType[2905] = "CS_REQ_SNS_PC_INFO" # Size = 0
packetsType[2906] = "CS_REQ_MARKET_LIST" # Size = 158
packetsType[2907] = "CS_REQ_MY_SELL_LIST" # Size = 10
packetsType[2908] = "CS_REQ_ADD_FRIEND" # Size = 70
packetsType[2909] = "CS_REQ_BLOCK_FRIEND" # Size = 70
packetsType[2910] = "CS_FRIEND_CMD" # Size = 24
packetsType[2911] = "CS_FRIEND_SET_ADDINFO" # Size = 160
packetsType[2912] = "CS_CHAT" # Size = 0
packetsType[2913] = "CS_CREATE_GROUP_CHAT" # Size = 6
packetsType[2914] = "CS_GROUP_CHAT_INVITE" # Size = 78
packetsType[2915] = "CS_REFRESH_GROUP_CHAT" # Size = 6
packetsType[2916] = "CS_CHAT_HISTORY" # Size = 22
packetsType[2917] = "CS_CHAT_READ" # Size = 30
packetsType[2918] = "CS_REMOVE_GROUP_MEMBER" # Size = 14
packetsType[2919] = "CS_PC_INTERACTION" # Size = 24
packetsType[2921] = "CS_PC_INTERACTION_HISTORY" # Size = 32
packetsType[2932] = "CS_ADD_RELATION_SCORE" # Size = 88
packetsType[2933] = "CS_GET_LIKE_COUNT" # Size = 16
packetsType[2929] = "CS_LIKE_IT" # Size = 80
packetsType[2930] = "CS_UNLIKE_IT" # Size = 16
packetsType[2931] = "CS_LIKE_IT_CONFIRM" # Size = 16
packetsType[2920] = "CS_REQ_RELATED_PC_SESSION" # Size = 16
packetsType[2922] = "CS_REDIS_SKILLPOINT" # Size = 22
packetsType[2923] = "CS_PARTY_CLIENT_INFO_SEND" # Size = 0
packetsType[2924] = "CS_NORMAL_GAME_START" # Size = 6
packetsType[2925] = "CS_PVP_COMMAND" # Size = 18
packetsType[2926] = "CS_REQUEST_PVP_RANKING" # Size = 83
packetsType[2927] = "CS_INVITE_PARTY_PVP" # Size = 10
packetsType[2928] = "CS_ACCEPT_PARTY_PVP" # Size = 19
packetsType[3001] = "CZ_CONNECT" # Size = 1164
packetsType[3070] = "CZ_GAME_READY" # Size = 10
packetsType[3081] = "CZ_KEYBOARD_MOVE" # Size = 41
packetsType[3082] = "CZ_EXPECTED_STOP_POS" # Size = 31
packetsType[3086] = "CZ_MOVE_PATH" # Size = 27
packetsType[3087] = "CZ_MOVE_STOP" # Size = 35
packetsType[3083] = "CZ_JUMP" # Size = 11
packetsType[3084] = "CZ_DASHRUN" # Size = 11
packetsType[3088] = "CZ_REST_SIT" # Size = 10
packetsType[3089] = "CZ_ON_AIR" # Size = 10
packetsType[3090] = "CZ_ON_GROUND" # Size = 10
packetsType[3085] = "CZ_SKILL_JUMP_REQ" # Size = 30
packetsType[3072] = "CZ_LOGOUT" # Size = 11
packetsType[3073] = "CZ_MOVE_BARRACK" # Size = 11
packetsType[3004] = "CZ_MOVE_ZONE_OK" # Size = 10
packetsType[3091] = "CZ_MOVEMENT_INFO" # Size = 23
packetsType[3092] = "CZ_SKILL_TARGET" # Size = 19
packetsType[3093] = "CZ_SKILL_TARGET_ANI" # Size = 23
packetsType[3094] = "CZ_SKILL_GROUND" # Size = 57
packetsType[3095] = "CZ_SKILL_SELF" # Size = 35
packetsType[3096] = "CZ_SKILL_CANCEL" # Size = 11
packetsType[3097] = "CZ_HOLD" # Size = 11
packetsType[3104] = "CZ_SHOUT" # Size = 0
packetsType[3102] = "CZ_CHAT" # Size = 0
packetsType[3103] = "CZ_CHAT_LOG" # Size = 0
packetsType[3107] = "CZ_ITEM_USE" # Size = 22
packetsType[3108] = "CZ_ITEM_USE_TO_ITEM" # Size = 30
packetsType[3109] = "CZ_ITEM_USE_TO_GROUND" # Size = 30
packetsType[3105] = "CZ_ITEM_DROP" # Size = 22
packetsType[3112] = "CZ_ITEM_EQUIP" # Size = 19
packetsType[3113] = "CZ_ITEM_UNEQUIP" # Size = 11
packetsType[3114] = "ZC_CHECK_INVINDEX" # Size = 30
packetsType[3106] = "CZ_ITEM_DELETE" # Size = 0
packetsType[3110] = "CZ_ITEM_BUY" # Size = 0
packetsType[3111] = "CZ_ITEM_SELL" # Size = 0
packetsType[3139] = "CZ_DIALOG_ACK" # Size = 14
packetsType[3140] = "CZ_DIALOG_SELECT" # Size = 11
packetsType[3141] = "CZ_DIALOG_STRINGINPUT" # Size = 138
packetsType[3026] = "CZ_LEAVE_TO_DUNGEON" # Size = 10
packetsType[3160] = "CZ_MOVE_CAMP" # Size = 18
packetsType[3161] = "CZ_CAMPINFO" # Size = 18
packetsType[3162] = "ZC_CAMPINFO" # Size = 18
packetsType[3080] = "CZ_CLICK_TRIGGER" # Size = 15
packetsType[3098] = "CZ_ROTATE" # Size = 18
packetsType[3099] = "CZ_HEAD_ROTATE" # Size = 18
packetsType[3100] = "CZ_TARGET_ROTATE" # Size = 18
packetsType[3101] = "CZ_POSE" # Size = 34
packetsType[3006] = "ZC_ENTER_PC" # Size = 370
packetsType[3007] = "ZC_ENTER_MONSTER" # Size = 0
packetsType[3008] = "ZC_ENTER_DUMMYPC" # Size = 292
packetsType[3009] = "ZC_UPDATED_DUMMYPC" # Size = 250
packetsType[3010] = "ZC_ENTER_ITEM" # Size = 103
packetsType[3011] = "ZC_LEAVE" # Size = 12
packetsType[3012] = "ZC_MOVE_PATH" # Size = 42
packetsType[3013] = "ZC_MOVE_POS" # Size = 42
packetsType[3016] = "ZC_MSPD" # Size = 14
packetsType[3017] = "ZC_MOVE_SPEED" # Size = 18
packetsType[3014] = "ZC_MOVE_DIR" # Size = 40
packetsType[3015] = "ZC_EXPECTED_STOPPOS" # Size = 35
packetsType[3018] = "ZC_MOVE_STOP" # Size = 23
packetsType[3019] = "ZC_REST_SIT" # Size = 11
packetsType[3020] = "ZC_JUMP" # Size = 19
packetsType[3021] = "ZC_JUMP_DIR" # Size = 34
packetsType[3022] = "ZC_ORDER_SKILL_JUMP" # Size = 10
packetsType[3023] = "ZC_SKILL_JUMP" # Size = 38
packetsType[3024] = "ZC_SET_POS" # Size = 22
packetsType[3025] = "ZC_FILE_MOVE" # Size = 46
packetsType[3076] = "ZC_MESSAGE" # Size = 0
packetsType[3002] = "ZC_CONNECT_OK" # Size = 0
packetsType[3005] = "ZC_CONNECT_FAILED" # Size = 0
packetsType[3078] = "ZC_START_GAME" # Size = 26
packetsType[3003] = "ZC_MOVE_ZONE" # Size = 7
packetsType[3074] = "ZC_MOVE_BARRACK" # Size = 6
packetsType[3071] = "ZC_MOVE_ZONE_OK" # Size = 57
packetsType[3056] = "ZC_DEAD" # Size = 0
packetsType[3057] = "ZC_RESURRECT" # Size = 18
packetsType[3059] = "ZC_RESURRECT_DIALOG" # Size = 7
packetsType[3067] = "CZ_RESURRECT" # Size = 11
packetsType[3068] = "ZC_RESURRECT_SAVE_POINT_ACK" # Size = 7
packetsType[3069] = "ZC_RESURRECT_HERE_ACK" # Size = 7
packetsType[3027] = "ZC_UPDATED_PCAPPEARANCE" # Size = 250
packetsType[3028] = "ZC_UPDATED_MONSTERAPPEARANCE" # Size = 0
packetsType[3032] = "ZC_ADD_HP" # Size = 22
packetsType[3136] = "ZC_UPDATE_SP" # Size = 15
packetsType[3138] = "ZC_UPDATE_MHP" # Size = 14
packetsType[3130] = "ZC_EXP_UP" # Size = 14
packetsType[3131] = "ZC_EXP_UP_BY_MONSTER" # Size = 18
packetsType[3132] = "ZC_PC_LEVELUP" # Size = 14
packetsType[3133] = "ZC_PC_STAT_AVG" # Size = 30
packetsType[3134] = "ZC_MAX_EXP_CHANGED" # Size = 18
packetsType[3171] = "ZC_UPDATE_ALL_STATUS" # Size = 26
packetsType[3058] = "ZC_CHANGE_RELATION" # Size = 11
packetsType[3122] = "ZC_QUICK_SLOT_LIST" # Size = 0
packetsType[3123] = "ZC_SKILL_LIST" # Size = 0
packetsType[3124] = "ZC_SKILL_ADD" # Size = 0
packetsType[3033] = "ZC_SKILL_CAST_CANCEL" # Size = 10
packetsType[3034] = "ZC_SKILL_CAST" # Size = 38
packetsType[3035] = "ZC_SKILL_READY" # Size = 46
packetsType[3037] = "ZC_SKILL_USE_CANCEL" # Size = 10
packetsType[3036] = "ZC_SKILL_DISABLE" # Size = 15
packetsType[3038] = "ZC_SKILL_MELEE_TARGET" # Size = 0
packetsType[3040] = "ZC_SKILL_FORCE_TARGET" # Size = 0
packetsType[3039] = "ZC_SKILL_MELEE_GROUND" # Size = 0
packetsType[3041] = "ZC_SKILL_FORCE_GROUND" # Size = 0
packetsType[3042] = "ZC_SKILL_HIT_INFO" # Size = 0
packetsType[3125] = "ZC_ABILITY_LIST" # Size = 0
packetsType[3126] = "CZ_ACTIVE_ABILITY" # Size = 15
packetsType[3127] = "ZC_ACTIVE_ABILITY" # Size = 11
packetsType[3128] = "CZ_DISPEL_DEBUFF_TOGGLE" # Size = 14
packetsType[3129] = "CZ_JUNGTAN_TOGGLE" # Size = 16
packetsType[3043] = "ZC_BUFF_LIST" # Size = 0
packetsType[3044] = "ZC_BUFF_ADD" # Size = 0
packetsType[3045] = "ZC_BUFF_UPDATE" # Size = 0
packetsType[3046] = "ZC_BUFF_REMOVE" # Size = 17
packetsType[3047] = "ZC_BUFF_CLEAR" # Size = 11
packetsType[3048] = "CZ_BUFF_REMOVE" # Size = 14
packetsType[3049] = "CZ_INTE_WARP" # Size = 14
packetsType[3060] = "ZC_HIT_INFO" # Size = 60
packetsType[3061] = "ZC_HEAL_INFO" # Size = 30
packetsType[3063] = "ZC_CAUTION_DAMAGE_INFO" # Size = 15
packetsType[3064] = "ZC_CAUTION_DAMAGE_RELEASE" # Size = 10
packetsType[3065] = "ZC_KNOCKBACK_INFO" # Size = 70
packetsType[3066] = "ZC_KNOCKDOWN_INFO" # Size = 71
packetsType[3029] = "ZC_CHAT" # Size = 0
packetsType[3030] = "ZC_CHAT_WITH_TEXTCODE" # Size = 14
packetsType[3174] = "ZC_SHOUT" # Size = 0
packetsType[3175] = "ZC_SHOUT_FAILED" # Size = 7
packetsType[3135] = "ZC_TEXT" # Size = 0
packetsType[3079] = "ZC_QUIET" # Size = 7
packetsType[3147] = "ZC_DIALOG_CLOSE" # Size = 6
packetsType[3143] = "ZC_DIALOG_OK" # Size = 0
packetsType[3144] = "ZC_DIALOG_NEXT" # Size = 0
packetsType[3145] = "ZC_DIALOG_SELECT" # Size = 0
packetsType[3148] = "ZC_DIALOG_TRADE" # Size = 39
packetsType[3149] = "ZC_DIALOG_COMMON_TRADE" # Size = 39
packetsType[3146] = "ZC_DIALOG_ITEM_SELECT" # Size = 0
packetsType[3150] = "ZC_DIALOG_NUMBERRANGE" # Size = 0
packetsType[3151] = "ZC_DIALOG_STRINGINPUT" # Size = 0
packetsType[3031] = "ZC_STANCE_CHANGE" # Size = 14
packetsType[3118] = "ZC_ITEM_ADD" # Size = 0
packetsType[3115] = "ZC_ITEM_INVENTORY_LIST" # Size = 0
packetsType[3116] = "ZC_ITEM_INVENTORY_INDEX_LIST" # Size = 0
packetsType[3117] = "ZC_ITEM_EQUIP_LIST" # Size = 0
packetsType[3119] = "ZC_ITEM_REMOVE" # Size = 20
packetsType[3120] = "ZC_ITEM_USE" # Size = 14
packetsType[3121] = "ZC_ITEM_USE_TO_GROUND" # Size = 22
packetsType[3077] = "ZC_RESET_VIEW" # Size = 6
packetsType[3137] = "ZC_RESTORATION" # Size = 12
packetsType[3050] = "ZC_ROTATE" # Size = 20
packetsType[3051] = "ZC_ROTATE_RESERVED" # Size = 18
packetsType[3052] = "ZC_HEAD_ROTATE" # Size = 18
packetsType[3053] = "ZC_TARGET_ROTATE" # Size = 18
packetsType[3054] = "ZC_QUICK_ROTATE" # Size = 18
packetsType[3055] = "ZC_POSE" # Size = 34
packetsType[3173] = "ZC_DUMP_PROPERTY" # Size = 0
packetsType[3172] = "ZC_OBJECT_PROPERTY" # Size = 0
packetsType[3152] = "ZC_ADDON_MSG" # Size = 0
packetsType[3153] = "CZ_UI_EVENT" # Size = 0
packetsType[3075] = "ZC_LOGOUT_OK" # Size = 6
packetsType[3154] = "ZC_PLAY_SOUND" # Size = 15
packetsType[3155] = "ZC_STOP_SOUND" # Size = 14
packetsType[3156] = "ZC_PLAY_MUSICQUEUE" # Size = 14
packetsType[3157] = "ZC_STOP_MUSICQUEUE" # Size = 14
packetsType[3158] = "ZC_PLAY_ANI" # Size = 24
packetsType[3159] = "ZC_CHANGE_ANI" # Size = 44
packetsType[3167] = "ZC_PLAY_ALARMSOUND" # Size = 83
packetsType[3168] = "ZC_STOP_ALARMSOUND" # Size = 10
packetsType[3169] = "ZC_PLAY_EXP_TEXT" # Size = 14
packetsType[3170] = "ZC_PLAY_NAVI_EFFECT" # Size = 150
packetsType[3176] = "CZ_EXCHANGE_REQUEST" # Size = 14
packetsType[3177] = "ZC_EXCHANGE_REQUEST_ACK" # Size = 72
packetsType[3178] = "ZC_EXCHANGE_REQUEST_RECEIVED" # Size = 71
packetsType[3179] = "CZ_EXCHANGE_ACCEPT" # Size = 10
packetsType[3180] = "CZ_EXCHANGE_DECLINE" # Size = 10
packetsType[3181] = "ZC_EXCHANGE_DECLINE_ACK" # Size = 6
packetsType[3182] = "ZC_EXCHANGE_START" # Size = 71
packetsType[3183] = "CZ_EXCHANGE_OFFER" # Size = 30
packetsType[3184] = "ZC_EXCHANGE_OFFER_ACK" # Size = 0
packetsType[3185] = "CZ_EXCHANGE_AGREE" # Size = 10
packetsType[3186] = "ZC_EXCHANGE_AGREE_ACK" # Size = 7
packetsType[3187] = "CZ_EXCHANGE_FINALAGREE" # Size = 10
packetsType[3188] = "ZC_EXCHANGE_FINALAGREE_ACK" # Size = 7
packetsType[3189] = "CZ_EXCHANGE_CANCEL" # Size = 10
packetsType[3190] = "ZC_EXCHANGE_CANCEL_ACK" # Size = 6
packetsType[3191] = "ZC_EXCHANGE_SUCCESS" # Size = 6
packetsType[3192] = "ZC_COOLDOWN_LIST" # Size = 0
packetsType[3193] = "ZC_COOLDOWN_CHANGED" # Size = 22
packetsType[3194] = "ZC_OVERHEAT_CHANGED" # Size = 26
packetsType[3195] = "ZC_TEST_AGENT" # Size = 18
packetsType[3196] = "CZ_COMMON_SHOP_LIST" # Size = 10
packetsType[3197] = "ZC_COMMON_SHOP_LIST" # Size = 8
packetsType[3198] = "ZC_TIME_FACTOR" # Size = 10
packetsType[3199] = "ZC_PARTY_ENTER" # Size = 0
packetsType[3200] = "ZC_PARTY_OUT" # Size = 24
packetsType[3201] = "ZC_PARTY_DESTROY" # Size = 15
packetsType[3202] = "ZC_PARTY_INFO" # Size = 0
packetsType[3203] = "ZC_PARTY_LIST" # Size = 0
packetsType[3204] = "ZC_PARTY_CHAT" # Size = 0
packetsType[3205] = "ZC_PARTY_INST_INFO" # Size = 0
packetsType[3206] = "ZC_CHANGE_EQUIP_DURABILITY" # Size = 11
packetsType[3207] = "CZ_DIALOG_TX" # Size = 0
packetsType[3208] = "CZ_REQ_RECIPE" # Size = 0
packetsType[3209] = "ZC_CUSTOM_DIALOG" # Size = 75
packetsType[3210] = "ZC_SESSION_OBJECTS" # Size = 0
packetsType[3211] = "ZC_SESSION_OBJ_ADD" # Size = 0
packetsType[3212] = "ZC_SESSION_OBJ_REMOVE" # Size = 10
packetsType[3213] = "ZC_SESSION_OBJ_TIME" # Size = 14
packetsType[3214] = "CZ_S_OBJ_VALUE_C" # Size = 24
packetsType[3215] = "CZ_REQ_NORMAL_TX" # Size = 29
packetsType[3216] = "ZC_COMMANDER_LOADER_INFO" # Size = 0
packetsType[3217] = "ZC_MOVE_SINGLE_ZONE" # Size = 18
packetsType[3218] = "ZC_BACKTO_ORIGINAL_SERVER" # Size = 8
packetsType[3219] = "CZ_BACKTO_ORIGINAL_SERVER" # Size = 12
packetsType[3220] = "CZ_REQ_NORMAL_TX_NUMARG" # Size = 0
packetsType[3221] = "ZC_WIKI_LIST" # Size = 0
packetsType[3222] = "ZC_WIKI_ADD" # Size = 22
packetsType[3223] = "CZ_WIKI_GET" # Size = 14
packetsType[3224] = "CZ_WIKI_RECIPE_UPDATE" # Size = 10
packetsType[3225] = "ZC_UI_OPEN" # Size = 39
packetsType[3226] = "ZC_ENABLE_CONTROL" # Size = 11
packetsType[3227] = "ZC_CHANGE_CAMERA" # Size = 31
packetsType[3228] = "ZC_MONSTER_SDR_CHANGED" # Size = 11
packetsType[3229] = "ZC_MOVE_IGNORE_COLLISION" # Size = 30
packetsType[3230] = "ZC_CHANGE_CAMERA_ZOOM" # Size = 34
packetsType[3231] = "ZC_PLAY_SKILL_ANI" # Size = 82
packetsType[3232] = "ZC_PLAY_SKILL_CAST_ANI" # Size = 30
packetsType[3233] = "CZ_REQ_ITEM_GET" # Size = 14
packetsType[3234] = "ZC_ITEM_GET" # Size = 18
packetsType[3235] = "CZ_GUARD" # Size = 19
packetsType[3236] = "ZC_GUARD" # Size = 19
packetsType[3237] = "ZC_STAMINA" # Size = 10
packetsType[3238] = "ZC_ADD_STAMINA" # Size = 10
packetsType[3239] = "ZC_GM_ORDER" # Size = 10
packetsType[3240] = "ZC_MYPC_ENTER" # Size = 18
packetsType[3241] = "ZC_LOCK_KEY" # Size = 75
packetsType[3242] = "ZC_SAVE_INFO" # Size = 6
packetsType[3243] = "CZ_SAVE_INFO" # Size = 0
packetsType[3244] = "ZC_OPTION_LIST" # Size = 0
packetsType[3245] = "ZC_SKILLMAP_LIST" # Size = 0
packetsType[3246] = "CZ_GIVEITEM_TO_DUMMYPC" # Size = 22
packetsType[3247] = "ZC_SET_LAYER" # Size = 10
packetsType[3248] = "ZC_CREATE_LAYERBOX" # Size = 38
packetsType[3249] = "ZC_RESET_BOX" # Size = 11
packetsType[3250] = "ZC_CREATE_SCROLLLOCKBOX" # Size = 38
packetsType[3251] = "ZC_REMOVE_SCROLLLOCKBOX" # Size = 10
packetsType[3252] = "CZ_DYNAMIC_CASTING_START" # Size = 23
packetsType[3253] = "CZ_DYNAMIC_CASTING_END" # Size = 19
packetsType[3254] = "CZ_SKILL_CANCEL_SCRIPT" # Size = 10
packetsType[3255] = "ZC_LEAVE_TRIGGER" # Size = 6
packetsType[3256] = "ZC_BORN" # Size = 10
packetsType[3257] = "ZC_ACHIEVE_POINT_LIST" # Size = 0
packetsType[3258] = "ZC_ACHIEVE_POINT" # Size = 18
packetsType[3259] = "CZ_ACHIEVE_EQUIP" # Size = 18
packetsType[3260] = "ZC_ACHIEVE_EQUIP" # Size = 22
packetsType[3261] = "CZ_CHANGE_CONFIG" # Size = 18
packetsType[3262] = "CZ_CHANGE_CONFIG_STR" # Size = 34
packetsType[3263] = "ZC_WORLD_MSG" # Size = 43
packetsType[3264] = "ZC_ENABLE_SHOW_ITEM_GET" # Size = 8
packetsType[3265] = "ZC_LOGIN_TIME" # Size = 14
packetsType[3266] = "ZC_GIVE_EXP_TO_PC" # Size = 42
packetsType[3267] = "ZC_LAYER_PC_LIST" # Size = 0
packetsType[3268] = "ZC_LAYER_PC_SOBJ_PROP" # Size = 0
packetsType[3269] = "CZ_CUSTOM_COMMAND" # Size = 26
packetsType[3424] = "CZ_ADD_HELP" # Size = 14
packetsType[3270] = "ZC_LAYER_INFO" # Size = 10
packetsType[3271] = "CZ_CHAT_MACRO" # Size = 146
packetsType[3272] = "ZC_CHAT_MACRO_LIST" # Size = 0
packetsType[3273] = "ZC_RULLET_LIST" # Size = 0
packetsType[3274] = "ZC_QUICKSLOT_REGISTER" # Size = 46
packetsType[3275] = "CZ_QUICKSLOT_LIST" # Size = 0
packetsType[3276] = "CZ_DOUBLE_ITEM_EQUIP" # Size = 28
packetsType[3277] = "ZC_TRICK_PACKET" # Size = 0
packetsType[3278] = "ZC_COOLDOWN_RATE" # Size = 22
packetsType[3279] = "ZC_MAP_REVEAL_LIST" # Size = 0
packetsType[3280] = "CZ_MAP_REVEAL_INFO" # Size = 146
packetsType[3281] = "CZ_MAP_SEARCH_INFO" # Size = 55
packetsType[3282] = "ZC_UI_INFO_LIST" # Size = 0
packetsType[3283] = "ZC_EXEC_CLIENT_SCP" # Size = 0
packetsType[3284] = "ZC_SET_NPC_STATE" # Size = 18
packetsType[3285] = "ZC_NPC_STATE_LIST" # Size = 0
packetsType[3286] = "CZ_QUEST_NPC_STATE_CHECK" # Size = 14
packetsType[3287] = "ZC_RANK_ACHIEVE_ADD" # Size = 14
packetsType[3288] = "CZ_GET_MAP_REVEAL_ACHIEVE" # Size = 10
packetsType[3289] = "CZ_IES_MODIFY_INFO" # Size = 0
packetsType[3290] = "ZC_IES_MODIFY_INFO" # Size = 0
packetsType[3291] = "ZC_IES_MODIFY_LIST" # Size = 0
packetsType[3292] = "CZ_IES_REVISION_DELETE" # Size = 0
packetsType[3293] = "ZC_IES_REVISION_DELETE" # Size = 0
packetsType[3294] = "ZC_EQUIP_ITEM_REMOVE" # Size = 18
packetsType[3295] = "ZC_SOLD_ITEM_LIST" # Size = 0
packetsType[3296] = "CZ_SOLD_ITEM" # Size = 19
packetsType[3297] = "CZ_WAREHOUSE_CMD" # Size = 31
packetsType[3298] = "CZ_SWAP_ETC_INV_CHANGE_INDEX" # Size = 35
packetsType[3299] = "CZ_SORT_ETC_INV_CHANGE_INDEX" # Size = 11
packetsType[3300] = "CZ_SORT_INV_CHANGE_INDEX" # Size = 11
packetsType[3301] = "CZ_CAST_CONTROL_SHOT" # Size = 10
packetsType[3302] = "ZC_PC_PROP_UPDATE" # Size = 9
packetsType[3303] = "CZ_CLIENT_DAMAGE" # Size = 14
packetsType[3304] = "CZ_CLIENT_ATTACK" # Size = 15
packetsType[3305] = "ZC_SYSTEM_MSG" # Size = 0
packetsType[3306] = "ZC_FSM_MOVE" # Size = 0
packetsType[3307] = "CZ_QUEST_CHECK_SAVE" # Size = 50
packetsType[3308] = "CZ_SPRAY_REQ_INFO" # Size = 14
packetsType[3309] = "CZ_SPRAY_DRAW_INFO" # Size = 0
packetsType[3310] = "ZC_SPRAY_ID" # Size = 18
packetsType[3311] = "ZC_SPRAY_DRAW_INFO" # Size = 0
packetsType[3312] = "ZC_MONSTER_LIFETIME" # Size = 14
packetsType[3313] = "ZC_SPRAY_LIKE_LIST" # Size = 0
packetsType[3314] = "ZC_WIKI_COUNT_UPDATE" # Size = 19
packetsType[3315] = "ZC_WIKI_INT_PROP_UPDATE" # Size = 15
packetsType[3316] = "ZC_WIKI_BOOL_PROP_UPDATE" # Size = 12
packetsType[3317] = "CZ_REQ_WIKI_RANK" # Size = 15
packetsType[3318] = "ZC_WIKI_RANK_LIST" # Size = 0
packetsType[3319] = "ZC_SHARED_MSG" # Size = 10
packetsType[3320] = "CZ_REQ_WIKI_PROP_RANK" # Size = 16
packetsType[3322] = "CZ_REQ_TX_ITEM" # Size = 0
packetsType[3323] = "ZC_TEST_DBG" # Size = 0
packetsType[3324] = "ZC_MONSTER_DIST" # Size = 0
packetsType[3325] = "ZC_RESET_SKILL_FORCEID" # Size = 10
packetsType[3326] = "ZC_EMOTICON" # Size = 18
packetsType[3327] = "ZC_SHOW_EMOTICON" # Size = 18
packetsType[3328] = "ZC_TREASUREMARK_BY_MAP" # Size = 0
packetsType[3329] = "ZC_SHOW_MAP" # Size = 0
packetsType[203] = "ZC_TREASUREMARK_LIST_MAP" # Size = 0
packetsType[3163] = "ZC_FIX_ANIM" # Size = 14
packetsType[3164] = "ZC_MOVE_ANIM" # Size = 12
packetsType[3330] = "CZ_FLEE_OBSTACLE" # Size = 26
packetsType[3331] = "ZC_HOLD_MOVE_PATH" # Size = 11
packetsType[3332] = "ZC_ENTER_HOOK" # Size = 10
packetsType[3333] = "ZC_LEAVE_HOOK" # Size = 10
packetsType[3334] = "ZC_MONSTER_PROPERTY" # Size = 0
packetsType[3335] = "ZC_GROUND_EFFECT" # Size = 50
packetsType[3336] = "ZC_FLY" # Size = 18
packetsType[3337] = "ZC_FLY_MATH" # Size = 22
packetsType[3338] = "ZC_FLY_HEIGHT" # Size = 14
packetsType[3339] = "ZC_UPDATE_SHIELD" # Size = 12
packetsType[3340] = "ZC_UPDATE_MSHIELD" # Size = 12
packetsType[3341] = "ZC_SHOW_MODEL" # Size = 15
packetsType[3342] = "ZC_SKILL_RANGE_DBG" # Size = 58
packetsType[3343] = "ZC_SKILL_RANGE_FAN" # Size = 40
packetsType[3344] = "ZC_SKILL_RANGE_SQUARE" # Size = 40
packetsType[3345] = "ZC_SKILL_RANGE_CIRCLE" # Size = 28
packetsType[3346] = "ZC_SKILL_RANGE_DONUTS" # Size = 32
packetsType[3347] = "ZC_TEAMID" # Size = 11
packetsType[3348] = "ZC_PC" # Size = 0
packetsType[3349] = "CZ_LOG" # Size = 0
packetsType[3350] = "ZC_MOTIONBLUR" # Size = 11
packetsType[3351] = "ZC_PLAY_FORCE" # Size = 78
packetsType[3352] = "ZC_CAST_TARGET" # Size = 14
packetsType[3353] = "ZC_START_INFO" # Size = 0
packetsType[3354] = "ZC_JOB_EXP_UP" # Size = 10
packetsType[3355] = "ZC_JOB_PTS" # Size = 10
packetsType[3356] = "ZC_MON_STAMINA" # Size = 22
packetsType[3357] = "CZ_CUSTOM_SCP" # Size = 14
packetsType[3358] = "ZC_VIEW_FOCUS" # Size = 24
packetsType[3359] = "ZC_HARDCODED_SKILL" # Size = 26
packetsType[3360] = "CZ_HARDCODED_SKILL" # Size = 34
packetsType[3361] = "ZC_FORCE_MOVE" # Size = 30
packetsType[3362] = "ZC_HSKILL_CONTROL" # Size = 22
packetsType[3363] = "ZC_CANCEL_DEADEVENT" # Size = 10
packetsType[3364] = "ZC_ACTION_PKS" # Size = 35
packetsType[3365] = "CZ_HARDCODED_ITEM" # Size = 22
packetsType[3367] = "CZ_BRIQUET" # Size = 30
packetsType[3366] = "CZ_CANCEL_TRANSFORM_SKILL" # Size = 10
packetsType[3368] = "ZC_VIBRATE" # Size = 30
packetsType[3369] = "ZC_COUNTER_MOVE" # Size = 10
packetsType[3370] = "CZ_COUNTER_ATTACK" # Size = 14
packetsType[3371] = "CZ_CLIENT_DIRECT" # Size = 30
packetsType[3372] = "ZC_CLIENT_DIRECT" # Size = 30
packetsType[3373] = "ZC_OWNER" # Size = 14
packetsType[3374] = "ZC_GD_RANK" # Size = 10
packetsType[3375] = "CZ_RUN_BGEVENT" # Size = 74
packetsType[3376] = "ZC_ADD_SKILL_EFFECT" # Size = 18
packetsType[3377] = "ZC_ITEM_DROPABLE" # Size = 10
packetsType[3378] = "CZ_ITEM_DROP_TO_OBJECT" # Size = 26
packetsType[3379] = "ZC_NORMAL" # Size = 0
packetsType[3380] = "CZ_G_QUEST_CHECK" # Size = 14
packetsType[3381] = "ZC_MOVE_PATH_MATH" # Size = 30
packetsType[3398] = "ZC_SHOW_GROUND_ITEM_MARK" # Size = 30
packetsType[3399] = "ZC_HELP_LIST" # Size = 0
packetsType[3400] = "ZC_HELP_ADD" # Size = 11
packetsType[3165] = "ZC_STD_ANIM" # Size = 11
packetsType[3401] = "CZ_CLIENT_HIT_LIST" # Size = 0
packetsType[3402] = "ZC_PC_ATKSTATE" # Size = 11
packetsType[3403] = "CZ_HELP_READ_TYPE" # Size = 18
packetsType[3404] = "CZ_MOVE_PATH_END" # Size = 10
packetsType[3405] = "ZC_COLL_DAMAGE" # Size = 11
packetsType[3406] = "CZ_KEYBOARD_BEAT" # Size = 10
packetsType[3407] = "CZ_MOVEHIT_SCP" # Size = 22
packetsType[3408] = "ZC_SYNC_START" # Size = 10
packetsType[3409] = "ZC_SYNC_END" # Size = 14
packetsType[3410] = "ZC_SYNC_EXEC" # Size = 10
packetsType[3411] = "ZC_SYNC_EXEC_BY_SKILL_TIME" # Size = 18
packetsType[3412] = "CZ_STOP_TIMEACTION" # Size = 11
packetsType[3413] = "CZ_REQ_DUMMYPC_INFO" # Size = 18
packetsType[3414] = "CZ_VISIT_BARRACK" # Size = 74
packetsType[3415] = "CZ_SPC_SKILL_POS" # Size = 22
packetsType[3416] = "CZ_REQ_CHANGEJOB" # Size = 14
packetsType[3419] = "CZ_REQ_MINITEXT" # Size = 266
packetsType[3420] = "ZC_PC_MOVE_STOP" # Size = 35
packetsType[3430] = "CZ_SKILL_TOOL_GROUND_POS" # Size = 26
packetsType[3417] = "CZ_CHANGE_HEAD" # Size = 14
packetsType[3418] = "CZ_CREATE_ARROW_CRAFT" # Size = 14
packetsType[3382] = "CZ_MYPAGE_COMMENT_ADD" # Size = 278
packetsType[3383] = "CZ_MYPAGE_COMMENT_DELETE" # Size = 18
packetsType[3385] = "CZ_GET_TARGET_MYPAGE" # Size = 14
packetsType[3386] = "CZ_ON_MYPAGE_MODE" # Size = 14
packetsType[3387] = "CZ_RESET_SOCIAL_MODE" # Size = 10
packetsType[3384] = "CZ_GUESTPAGE_COMMENT_ADD" # Size = 278
packetsType[3388] = "CZ_GET_TARGET_GUESTPAGE" # Size = 14
packetsType[3389] = "CZ_ADD_SELLMODE_ITEM" # Size = 30
packetsType[3390] = "CZ_DELETE_SELLMODE_ITEM" # Size = 18
packetsType[3391] = "CZ_ON_SELLITEM_MODE" # Size = 14
packetsType[3396] = "CZ_ON_ITEMBUY_MODE" # Size = 0
packetsType[3392] = "ZC_MYPAGE_MAP" # Size = 0
packetsType[3393] = "ZC_GUESTPAGE_MAP" # Size = 0
packetsType[3394] = "ZC_ON_MYPAGE_MODE" # Size = 0
packetsType[3395] = "ZC_RESET_SOCIAL_MODE" # Size = 10
packetsType[3397] = "ZC_ON_BUYITEM_MODE" # Size = 0
packetsType[3421] = "CZ_STOP_ALLPC" # Size = 10
packetsType[3422] = "CZ_COMPLETE_PRELOAD" # Size = 14
packetsType[3423] = "CZ_MGAME_JOIN_CMD" # Size = 46
packetsType[3425] = "ZC_ATTACH_TO_OBJ" # Size = 49
packetsType[3426] = "ZC_DETACH_FROM_OBJ" # Size = 14
packetsType[3427] = "ZC_RUN_FROM" # Size = 14
packetsType[3428] = "ZC_LOOKAT_OBJ" # Size = 14
packetsType[3429] = "CZ_SKILL_CELL_LIST" # Size = 0
packetsType[3431] = "CZ_DIRECTION_PROCESS" # Size = 18
packetsType[3432] = "CZ_DIRECTION_MOVE_STATE" # Size = 0
packetsType[3433] = "ZC_TO_ALL_CLIENT" # Size = 0
packetsType[3434] = "ZC_TO_CLIENT" # Size = 0
packetsType[3435] = "CZ_REWARD_CMD" # Size = 14
packetsType[3436] = "CZ_PROPERTY_COMPARE" # Size = 15
packetsType[3437] = "ZC_PROPERTY_COMPARE" # Size = 0
packetsType[3497] = "ZC_RECOMMEND_PARTYMEMBER_INFO" # Size = 0
packetsType[3438] = "ZC_FACTION" # Size = 14
packetsType[3439] = "ZC_BEGIN_KILL_LOG" # Size = 6
packetsType[3440] = "ZC_END_KILL_LOG" # Size = 6
packetsType[3441] = "ZC_CLEAR_KILL_LOG" # Size = 6
packetsType[3442] = "CZ_NPC_AUCTION_CMD" # Size = 30
packetsType[3443] = "ZC_DIRECTION_APC" # Size = 22
packetsType[3444] = "ZC_BGMODEL_ANIM_INFO" # Size = 15
packetsType[3445] = "ZC_ATTACH_BY_KNOCKBACK" # Size = 38
packetsType[3446] = "CZ_OBJECT_MOVE" # Size = 30
packetsType[3447] = "CZ_CONTROL_OBJECT_ROTATE" # Size = 22
packetsType[3448] = "CZ_SUMMON_COMMAND" # Size = 18
packetsType[3449] = "CZ_VEHICLE_RIDE" # Size = 15
packetsType[3450] = "CZ_REQ_WIKI_CATEGORY_RANK_PAGE_INFO" # Size = 78
packetsType[3451] = "CZ_REQ_ACHIEVE_RANK_PAGE_INFO" # Size = 78
packetsType[3452] = "CZ_REQ_MONSTER_RANK_INFO" # Size = 74
packetsType[3453] = "ZC_SPC_TRIGGER_EXEC" # Size = 30
packetsType[3454] = "CZ_REQ_MGAME_VIEW" # Size = 18
packetsType[3455] = "CZ_REQ_MGAME_CHAT" # Size = 0
packetsType[3456] = "CZ_TOURNAMENT_GIFT" # Size = 18
packetsType[3457] = "CZ_PARTY_INVITE_ACCEPT" # Size = 79
packetsType[3458] = "CZ_PARTY_INVITE_CANCEL" # Size = 83
packetsType[3459] = "CZ_PARTY_PROP_CHANGE" # Size = 145
packetsType[3460] = "CZ_REQ_MARKET_REGISTER" # Size = 27
packetsType[3461] = "CZ_REQ_MARKET_BUY" # Size = 0
packetsType[3462] = "CZ_REQ_CABINET_LIST" # Size = 10
packetsType[3463] = "CZ_REQ_GET_CABINET_ITEM" # Size = 26
packetsType[3464] = "CZ_REQ_CANCEL_MARKET_ITEM" # Size = 18
packetsType[3465] = "CZ_OBJ_RECORD_POS" # Size = 0
packetsType[3466] = "CZ_FORMATION_CMD" # Size = 32
packetsType[3467] = "CZ_REGISTER_AUTOSELLER" # Size = 0
packetsType[3468] = "CZ_OPEN_AUTOSELLER" # Size = 34
packetsType[3469] = "CZ_BUY_AUTOSELLER_ITEMS" # Size = 0
packetsType[3470] = "CZ_SELL_MY_AUTOSELLER_ITEMS" # Size = 0
packetsType[3471] = "CZ_PUZZLE_CRAFT" # Size = 0
packetsType[3321] = "CZ_GET_WIKI_REWARD" # Size = 11
packetsType[3472] = "CZ_PET_EQUIP" # Size = 30
packetsType[3473] = "ZC_FOUND_PARTY_LIST" # Size = 0
packetsType[3474] = "ZC_RECOMMEND_PARTY_INFO" # Size = 0
packetsType[3475] = "CZ_REQUEST_SOME_PARTY" # Size = 90
packetsType[3476] = "CZ_REFRESH_MEMBERRECOMMEND_LIST" # Size = 10
packetsType[3477] = "ZC_TO_SOMEWHERE_CLIENT" # Size = 0
packetsType[3478] = "CZ_REVEAL_NPC_STATE" # Size = 14
packetsType[3479] = "CZ_CHANGE_CHANNEL" # Size = 12
packetsType[3480] = "CZ_REQ_CHANNEL_TRAFFICS" # Size = 12
packetsType[3481] = "CZ_BUY_PROPERTYSHOP_ITEM" # Size = 0
packetsType[3482] = "CZ_SKILL_USE_HEIGHT" # Size = 14
packetsType[3483] = "CZ_ACCEPT_PARTY_QUEST" # Size = 20
packetsType[3484] = "CZ_ACCEPT_PARTY_EVENT" # Size = 20
packetsType[3485] = "CZ_DELETE_PARTY_EVENT" # Size = 20
packetsType[3486] = "CZ_PING" # Size = 10
packetsType[3487] = "ZC_PING" # Size = 10
packetsType[3488] = "ZC_XIGNCODE_BUFFER" # Size = 524
packetsType[3489] = "CZ_XIGNCODE_BUFFER" # Size = 524
packetsType[3490] = "CZ_CHANGE_TITLE" # Size = 74
packetsType[3491] = "CZ_PC_COMMENT_CHANGE" # Size = 0
packetsType[3492] = "CZ_AUTTOSELLER_BUYER_CLOSE" # Size = 18
packetsType[3493] = "CZ_REQ_ITEM_LIST" # Size = 11
packetsType[3494] = "CZ_HIT_MISSILE" # Size = 14
packetsType[3495] = "CZ_I_NEED_PARTY" # Size = 23
packetsType[3496] = "CZ_PARTY_JOIN_BY_LINK" # Size = 19
packetsType[3498] = "CZ_PVP_ZONE_CMD" # Size = 22
packetsType[3499] = "CZ_PVP_CHAT" # Size = 0
packetsType[3500] = "CZ_CARDBATTLE_CMD" # Size = 26

# Search "SkillAdd" or "AbilityList"
packetFunctionProfiler = 0x415960;

class JumpTableHandler:

    def __init__ (self, jumptableOffset, jumptableSize, jumptableIndex, jumptableAddress, defaultCase, className):
        self.jumptableOffset = jumptableOffset;
        self.jumptableSize = jumptableSize;
        self.jumptableIndex = jumptableIndex;
        self.jumptableAddress = jumptableAddress;
        self.defaultCase = defaultCase;
        self.className = className;

    def resolve (self, isZone):
        for n in range (self.jumptableSize):
            # Get jumptable entry
            namePacketFunctionSeen = 0;
            index = Byte (self.jumptableIndex + n);
            address = Dword (self.jumptableAddress + index*4);

            # Default case
            if address == self.defaultCase:
                continue;

            # Get the first call or the first call after the packetFunctionProfiler
            callOk = False;
            newPacketFunctionCalled = False;

            while callOk == False:
                if GetMnem (address) == "call":
                    if isZone == False:
                        callOk = True;
                    else:
                        callAddress = GetOperandValue (address, 0);
                        if callAddress == packetFunctionProfiler:
                            newPacketFunctionCalled = True;
                        elif newPacketFunctionCalled == True:
                            callOk = True;
                if callOk == False:
                    address = NextHead (address);

            # Get the name in the packets list
            name = packetsType[n+self.jumptableOffset];

            if name != None:
                callAddress = GetOperandValue (address, 0);
                if GetOpnd (address, 0) == "ds:delete":
                    continue;
                if callAddress < 0x400000:
                    continue;
                print "%x => %s" % (callAddress, self.className + "::" + name);
                MakeName (callAddress, self.className + "::" + name);


# Barrack
jumptableOffset  = 13
jumptableSize    = 0x4F
jumptableIndex   = 0x44B178
jumptableAddress = 0x44B128
defaultCase      = 0x44B109
barrackHandler = JumpTableHandler (jumptableOffset, jumptableSize, jumptableIndex, jumptableAddress, defaultCase, "CBarrackNet");
barrackHandler.resolve (False);


# Zone : ProcessPacket
jumptableOffset  = 0xC2B
jumptableSize    = 0x175
jumptableIndex   = 0x41D044
jumptableAddress = 0x41CDF8
defaultCase      = 0x41CCBC
zoneHandler1 = JumpTableHandler (jumptableOffset, jumptableSize, jumptableIndex, jumptableAddress, defaultCase, "CNormalNet");
zoneHandler1.resolve (True);


# Zone : ProcessCommonPackets
jumptableOffset  = 0xBBE
jumptableSize    = 0x1D7
jumptableIndex   = 0x666840
jumptableAddress = 0x666658
defaultCase      = 0x666637
zoneHandler2 = JumpTableHandler (jumptableOffset, jumptableSize, jumptableIndex, jumptableAddress, defaultCase, "CNormalNet");
zoneHandler2.resolve (True);