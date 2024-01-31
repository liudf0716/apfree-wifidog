// include json-c/json.h header
#include <json-c/json.h>
#include <stdio.h>
#include <string.h>

#define debug(log_level, fmt, args...) printf(fmt, ##args)

/*
 * write a function to parse the json string as the following format
 * the function has three parameters, the first is the json string, 
 * the second is the ip address, the third is the mac address
 * the function parse the json string and find the rule which match the ip and mac address
 * if the rule is found, return the handle of the rule, otherwise return -1
 * the json string is the output of the command "nft list ruleset  -j"
 * the function name is "get_nftables_rule_handle_by_ip_mac(json_object *jobj, const char *ip, const char *mac)"
 * the following is the json string format
 * 
`
{
   "nftables":[
      {
         "metainfo":{
            "version":"1.0.2",
            "release_name":"Lester Gooch",
            "json_schema_version":1
         }
      },
      {
         "chain":{
            "family":"inet",
            "table":"fw4",
            "name":"mangle_prerouting_wifidogx_outgoing",
            "handle":107
         }
      },
      {
         "rule":{
            "family":"inet",
            "table":"fw4",
            "chain":"mangle_prerouting_wifidogx_outgoing",
            "handle":124,
            "expr":[
               {
                  "match":{
                     "op":"==",
                     "left":{
                        "payload":{
                           "protocol":"ether",
                           "field":"saddr"
                        }
                     },
                     "right":"00:50:56:c0:00:03"
                  }
               },
               {
                  "match":{
                     "op":"==",
                     "left":{
                        "payload":{
                           "protocol":"ip",
                           "field":"saddr"
                        }
                     },
                     "right":"192.168.80.18"
                  }
               },
               {
                  "counter":{
                     "packets":12532,
                     "bytes":3187137
                  }
               },
               {
                  "mangle":{
                     "key":{
                        "meta":{
                           "key":"mark"
                        }
                     },
                     "value":131072
                  }
               },
               {
                  "accept":null
               }
            ]
         }
      }
   ]
}
`
*/

static int
check_nft_expr_json_array_object(json_object *jobj, const char *ip, const char *mac)
{
    // get the array length
    int arraylen = json_object_array_length(jobj);
    int i = 0;
    int ip_flag = 0;
    int mac_flag = 0;
    if (mac == NULL) {
        // do not check mac address
        mac_flag = 1;
    }
    // iterate the array
    for (i = 0; i < arraylen; i++) {
        json_object *jobj_item = json_object_array_get_idx(jobj, i);
        json_object *jobj_item_match = NULL;
        if (json_object_object_get_ex(jobj_item, "match", &jobj_item_match)) {
            // if the item contains "match", get the "match" object
            json_object *jobj_item_match_left = NULL;
            json_object *jobj_item_match_right = NULL;
            if (json_object_object_get_ex(jobj_item_match, "left", &jobj_item_match_left)) {
                // if the "match" object contains "left", get the "left" object
                json_object *jobj_item_match_left_payload = NULL;
                if (json_object_object_get_ex(jobj_item_match_left, "payload", &jobj_item_match_left_payload)) {
                    // if the "left" object contains "payload", get the "payload" object
                    json_object *jobj_item_match_left_payload_protocol = NULL;
                    if (json_object_object_get_ex(jobj_item_match_left_payload, "protocol", &jobj_item_match_left_payload_protocol)) {
                        // if the "payload" object contains "protocol", get the "protocol" value
                        const char *protocol = json_object_get_string(jobj_item_match_left_payload_protocol);
                        if (strcmp(protocol, "ether") == 0) {
                            // if the "protocol" value is "ether", get the "right" value
                            if (json_object_object_get_ex(jobj_item_match, "right", &jobj_item_match_right)) {
                                const char *right = json_object_get_string(jobj_item_match_right);
                                if (strcmp(right, mac) != 0) {
                                    // if the "right" value is the mac address, return 1
                                    mac_flag = 1;
                                }
                            }
                        } else if (strcmp(protocol, "ip") == 0) {
                            // if the "protocol" value is "ip", get the "right" value
                            if (json_object_object_get_ex(jobj_item_match, "right", &jobj_item_match_right)) {
                                const char *right = json_object_get_string(jobj_item_match_right);
                                if (strcmp(right, ip) != 0) {
                                    // if the "right" value is the ip address, return 1
                                    ip_flag = 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        // if ip_flag and mac_flag are both 1, return 1
        if (ip_flag == 1 && mac_flag == 1) {
            return 1;
        } 
    }
    
    return 0;
}

/*
 * delete client from firewall
 */
static void
nft_fw_del_rule_by_ip_and_mac(const char *ip, const char *mac, const char *chain)
{
    // iterate chain mangle_prerouting_wifidogx_outgoing, 
    // if the rule contains the ip and mac, delete the rule
    // first get the rule list of chain mangle_prerouting_wifidogx_outgoing
    char cmd[256] = {0};
    snprintf(cmd, sizeof(cmd), "nft -j list chain inet fw4 %s", chain);
    // throught popen, get the rule list of chain mangle_prerouting_wifidogx_outgoing
    FILE *r_fp = popen(cmd, "r");
    if (r_fp == NULL) {
        debug(LOG_ERR, " popen failed");
        return;
    }
    char buf[4096] = {0};
    // read the rule list of chain mangle_prerouting_wifidogx_outgoing
    fgets(buf, sizeof(buf), r_fp);
    pclose(r_fp);
    // parse the rule list of chain mangle_prerouting_wifidogx_outgoing
    // use libjson-c to parse the rule list of chain mangle_prerouting_wifidogx_outgoing
    json_object *jobj = json_tokener_parse(buf);
    if (jobj == NULL) {
        debug(LOG_ERR, " jobj is NULL");
        return;
    }
    // get the "nftables" json object which is an array of json objects
	json_object *jobj_nftables = NULL;
	if (!json_object_object_get_ex(jobj, "nftables", &jobj_nftables)) {
		debug(LOG_ERR, " jobj_nftables is NULL");
		goto END_DELETE_CLIENT;
	}
    // iterate the array of json objects to find the rule which contains the ip and mac
    int i = 0;
    int len = json_object_array_length(jobj_nftables);
    for (i = 0; i < len; i++) {
        json_object *jobj_rule = json_object_array_get_idx(jobj_nftables, i);
        if (jobj_rule == NULL) {
            debug(LOG_ERR, " jobj_rule is NULL");
            continue;
        }
        // get the "rule" json object which is an array of json objects
        json_object *jobj_rule_rule = NULL;
        if (!json_object_object_get_ex(jobj_rule, "rule", &jobj_rule_rule)) {
            debug(LOG_ERR, "jobj_rule_rule is NULL");
            continue;
        }
        // get the "expr" json object which is an array of json objects
        json_object *jobj_rule_expr = NULL;
        if (!json_object_object_get_ex(jobj_rule_rule, "expr", &jobj_rule_expr)) {
            debug(LOG_ERR, "jobj_rule_expr is NULL");
            continue;
        }
        // use the function check_nft_expr_json_array_object to check if the rule contains the ip and mac
        if (check_nft_expr_json_array_object(jobj_rule_expr, ip, mac) == 1) {
            // if the rule contains the ip and mac, get the "handle" value
            json_object *jobj_rule_handle = NULL;
            if (!json_object_object_get_ex(jobj_rule, "handle", &jobj_rule_handle)) {
                debug(LOG_ERR, "jobj_rule_handle is NULL");
                continue;
            }
            const char *handle = json_object_get_string(jobj_rule_handle);
            // delete the rule
            char cmd[256] = {0};
            snprintf(cmd, sizeof(cmd), "nft delete rule inet fw4 %s handle %s", chain, handle);
            //run_cmd(cmd);
        }
    }

END_DELETE_CLIENT:
    json_object_put(jobj);
}

int main(int argc, char *argv[])
{
    if (argc != 4) {
        printf("Usage: %s ip mac chain", argv[0]);
        return -1;
    }
    nft_fw_del_rule_by_ip_and_mac(argv[1], argv[2], argv[3]);
    return 0;
}