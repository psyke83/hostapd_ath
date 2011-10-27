
#include "includes.h"
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <net/if_arp.h>

#include "wireless_copy.h"
#include "common.h"
#include "eloop.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_common.h"
#include "priv_netlink.h"
#include "netlink.h"
#include "linux_ioctl.h"
#include "driver.h"
#include <net/if.h>
#include "ap/hostapd.h"
#include "ap/ap_config.h"
#undef WPA_OUI_TYPE
#undef WMM_OUI_TYPE
#include <athdefs.h>
#include <a_types.h>
#include <a_osapi.h>
#include <wmi.h>
#include <athdrv_linux.h>
#include <athtypes_linux.h>
#include <ieee80211.h>
#include <ieee80211_ioctl.h>
#include "radius/radius.h"

#include "l2_packet/l2_packet.h"
#include "ap/sta_info.h"
#include "ap/ieee802_1x.h"
#include "ap/wpa_auth.h"
#include "ap/accounting.h"
#include "ap/wps_hostapd.h"
#include "p2p/p2p.h"

struct ar6003_driver_data {
    void *ctx;
    struct netlink_data *netlink;
    int ioctl_sock;
    int mlme_sock;
    char ifname[IFNAMSIZ + 1];
    int ifindex;
    int ifindex2;
    int if_removed;
    u8 *assoc_req_ies;
    size_t assoc_req_ies_len;
    u8 *assoc_resp_ies;
    size_t assoc_resp_ies_len;
    struct wpa_driver_capa capa;
    int has_capability;
    int we_version_compiled;

    /* for set_auth_alg fallback */
    int use_crypt;
    int auth_alg_fallback;

    int operstate;

    char mlmedev[IFNAMSIZ + 1];

    int scan_complete_events;

    int cfg80211; /* whether driver is using cfg80211 */

    struct l2_packet_data *sock_xmit;   /* raw packet xmit socket */
    struct l2_packet_data *sock_recv;   /* raw packet recv socket */
    int we_version;
    int wext_sock;                     /* socket for wireless events */
    struct hostap_sta_driver_data acct_data;
    struct l2_packet_data *sock_raw; /* raw 802.11 management frames */
    u8  acct_mac[ETH_ALEN];

};

static int p2p_state ;
enum p2p_states {UNINTIALIZED, P2PNEGOCOMPLETE};
//static int p2p_state = P2PNEGOCOMPLETE ;

int ar6003_driver_get_bssid(void *priv, u8 *bssid);
int ar6003_driver_set_bssid(void *priv, const u8 *bssid);
int ar6003_driver_get_ssid(void *priv, u8 *ssid);
int ar6003_driver_set_ssid(void *priv, const u8 *ssid, size_t ssid_len);
int ar6003_driver_set_freq(void *priv, int freq);
int ar6003_driver_set_mode(void *priv, int mode);
int ar6003_driver_set_key(const char *ifname, void *priv, enum wpa_alg alg,
            const u8 *addr, int key_idx,
            int set_tx, const u8 *seq, size_t seq_len,
            const u8 *key, size_t key_len);
int ar6003_driver_scan(void *priv, struct wpa_driver_scan_params *params);
struct wpa_scan_results * ar6003_driver_get_scan_results(void *priv);

void ar6003_driver_scan_timeout(void *eloop_ctx, void *timeout_ctx);

int ar6003_driver_alternative_ifindex(struct ar6003_driver_data *drv,
                const char *ifname);

void * ar6003_driver_init(void *ctx, const char *ifname);
void ar6003_driver_deinit(void *priv);

int ar6003_driver_set_operstate(void *priv, int state);
int ar6003_driver_get_version(struct ar6003_driver_data *drv);

int ar6003_driver_associate(void *priv,
              struct wpa_driver_associate_params *params);
int ar6003_driver_get_capa(void *priv, struct wpa_driver_capa *capa);
int ar6003_driver_set_auth_param(struct ar6003_driver_data *drv,
               int idx, u32 value);
int ar6003_driver_cipher2wext(int cipher);
int ar6003_driver_keymgmt2wext(int keymgmt);
static int ar6003_driver_flush_pmkid(void *priv);
static int ar6003_driver_get_range(void *priv);
static int ar6003_driver_finish_drv_init(struct ar6003_driver_data *drv);
static void ar6003_driver_disconnect(struct ar6003_driver_data *drv);
static int ar6003_driver_set_auth_alg(void *priv, int auth_alg);




static int set80211param(struct ar6003_driver_data *drv, int op, int arg);
static void
ar6003_wireless_event_deinit(void *priv)
{
    struct ar6003_driver_data *drv = priv;

    if (drv != NULL) {
    if (drv->wext_sock < 0)
        return;
    eloop_unregister_read_sock(drv->wext_sock);
    close(drv->wext_sock);
    }
}

static int
set80211priv(struct ar6003_driver_data *drv, int op, void *data, int len)
{
    struct iwreq iwr;

    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.data.pointer = data;
    iwr.u.data.length = len;

    if (ioctl(drv->ioctl_sock, op, &iwr) < 0) {
    int first = IEEE80211_IOCTL_SETPARAM;
    static const char *opnames[] = {
        "ioctl[IEEE80211_IOCTL_SETPARAM]",
        "ioctl[IEEE80211_IOCTL_SETKEY]",
        "ioctl[IEEE80211_IOCTL_DELKEY]",
        "ioctl[IEEE80211_IOCTL_SETMLME]",
        "ioctl[IEEE80211_IOCTL_ADDPMKID]",
        "ioctl[IEEE80211_IOCTL_SETOPTIE]",
        "ioctl[SIOCIWFIRSTPRIV+6]",
        "ioctl[SIOCIWFIRSTPRIV+7]",
        "ioctl[SIOCIWFIRSTPRIV+8]",
        "ioctl[SIOCIWFIRSTPRIV+9]",
        "ioctl[SIOCIWFIRSTPRIV+10]",
        "ioctl[SIOCIWFIRSTPRIV+11]",
        "ioctl[SIOCIWFIRSTPRIV+12]",
        "ioctl[SIOCIWFIRSTPRIV+13]",
        "ioctl[SIOCIWFIRSTPRIV+14]",
        "ioctl[SIOCIWFIRSTPRIV+15]",
        "ioctl[SIOCIWFIRSTPRIV+16]",
        "ioctl[SIOCIWFIRSTPRIV+17]",
        "ioctl[SIOCIWFIRSTPRIV+18]",
    };
    int idx = op - first;
    if (first <= op &&
        idx < (int) (sizeof(opnames) / sizeof(opnames[0])) &&
        opnames[idx])
        perror(opnames[idx]);
    else
        perror("ioctl[unknown???]");
    return -1;
    }
    return 0;
}
static const char *
ether_sprintf(const u8 *addr)
{
    static char buf[sizeof(MACSTR)];

    if (addr != NULL)
    snprintf(buf, sizeof(buf), MACSTR, MAC2STR(addr));
    else
    snprintf(buf, sizeof(buf), MACSTR, 0,0,0,0,0,0);
    return buf;
}


static int ar6003_driver_capa(struct ar6003_driver_data *drv)
{
    drv->has_capability = 1;
    /* For now, assume TKIP, CCMP, WPA, WPA2 are supported */

    drv->capa.key_mgmt = WPA_DRIVER_CAPA_KEY_MGMT_WPA |
    WPA_DRIVER_CAPA_KEY_MGMT_WPA_PSK |
    WPA_DRIVER_CAPA_KEY_MGMT_WPA2 |
    WPA_DRIVER_CAPA_KEY_MGMT_WPA2_PSK;
    drv->capa.enc = WPA_DRIVER_CAPA_ENC_WEP40 |
    WPA_DRIVER_CAPA_ENC_WEP104 |
    WPA_DRIVER_CAPA_ENC_TKIP |
    WPA_DRIVER_CAPA_ENC_CCMP;
    drv->capa.auth = WPA_DRIVER_AUTH_OPEN |
    WPA_DRIVER_AUTH_SHARED ;
    drv->capa.flags |= WPA_DRIVER_FLAGS_AP;

    drv->capa.flags |= WPA_DRIVER_FLAGS_SET_KEYS_AFTER_ASSOC_DONE;

    return 0;
}
int ar6003_driver_set_auth_param(struct ar6003_driver_data *drv,
               int idx, u32 value)
{
    struct iwreq iwr;
    int ret = 0;

    wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);
    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.param.flags = idx & IW_AUTH_INDEX;
    iwr.u.param.value = value;

    
    if (ioctl(drv->ioctl_sock, SIOCSIWAUTH, &iwr) < 0) {
    if (errno != EOPNOTSUPP) {
        wpa_printf(MSG_DEBUG, "SIOCSIWAUTH(param %d "
               "value 0x%x) failed: %s)",
               idx, value, strerror(errno));
    }
    ret = errno == EOPNOTSUPP ? -2 : -1;
    }

    return ret;
}


/**
 * ar6003_driver_get_bssid - Get BSSID, SIOCGIWAP
 * @priv: Pointer to private data from ar6003_driver_init()
 * @bssid: Buffer for BSSID
 * Returns: 0 on success, -1 on failure
 */
int ar6003_driver_get_bssid(void *priv, u8 *bssid)
{
    struct ar6003_driver_data *drv = priv;
    struct iwreq iwr;
    int ret = 0;

    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);

    if (ioctl(drv->ioctl_sock, SIOCGIWAP, &iwr) < 0) {
    perror("ioctl[SIOCGIWAP]");
    ret = -1;
    }
    os_memcpy(bssid, iwr.u.ap_addr.sa_data, ETH_ALEN);

    return ret;
}


/**
 * ar6003_driver_set_bssid - Set BSSID, SIOCSIWAP
 * @priv: Pointer to private data from ar6003_driver_init()
 * @bssid: BSSID
 * Returns: 0 on success, -1 on failure
 */
int ar6003_driver_set_bssid(void *priv, const u8 *bssid)
{
    struct ar6003_driver_data *drv = priv;
    struct iwreq iwr;
    int ret = 0;

    wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);
    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.ap_addr.sa_family = ARPHRD_ETHER;
    if (bssid)
    os_memcpy(iwr.u.ap_addr.sa_data, bssid, ETH_ALEN);
    else
    os_memset(iwr.u.ap_addr.sa_data, 0, ETH_ALEN);

    if (ioctl(drv->ioctl_sock, SIOCSIWAP, &iwr) < 0) {
    perror("ioctl[SIOCSIWAP]");
    ret = -1;
    }

    return ret;
}


/**
 * ar6003_driver_get_ssid - Get SSID, SIOCGIWESSID
 * @priv: Pointer to private data from ar6003_driver_init()
 * @ssid: Buffer for the SSID; must be at least 32 bytes long
 * Returns: SSID length on success, -1 on failure
 */
int ar6003_driver_get_ssid(void *priv, u8 *ssid)
{
    struct ar6003_driver_data *drv = priv;
    struct iwreq iwr;
    int ret = 0;

    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.essid.pointer = (caddr_t) ssid;
    iwr.u.essid.length = 32;

    if (ioctl(drv->ioctl_sock, SIOCGIWESSID, &iwr) < 0) {
    perror("ioctl[SIOCGIWESSID]");
    ret = -1;
    } else {
    ret = iwr.u.essid.length;
    if (ret > 32)
        ret = 32;
    /* Some drivers include nul termination in the SSID, so let's
     * remove it here before further processing. WE-21 changes this
     * to explicitly require the length _not_ to include nul
     * termination. */
    if (ret > 0 && ssid[ret - 1] == '\0' &&
        drv->we_version_compiled < 21)
        ret--;
    }

    return ret;
}


/**
 * ar6003_driver_set_ssid - Set SSID, SIOCSIWESSID
 * @priv: Pointer to private data from ar6003_driver_init()
 * @ssid: SSID
 * @ssid_len: Length of SSID (0..32)
 * Returns: 0 on success, -1 on failure
 */
int ar6003_driver_set_ssid(void *priv, const u8 *ssid, size_t ssid_len)
{
    struct ar6003_driver_data *drv = priv;
    struct iwreq iwr;
    int ret = 0;
    char buf[33];


    wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);
    /*if(p2p_state != P2PNEGOCOMPLETE)
    return -1;
    */

    if (ssid_len > 32)
    return -1;

    wpa_printf(MSG_DEBUG, "ssid len=%d",ssid_len);
    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    /* flags: 1 = ESSID is active, 0 = not (promiscuous) */
    iwr.u.essid.flags = (ssid_len != 0);
    os_memset(buf, 0, sizeof(buf));
    os_memcpy(buf, ssid, ssid_len);
    iwr.u.essid.pointer = (caddr_t) buf;
    if (drv->we_version_compiled < 21) {
    /* For historic reasons, set SSID length to include one extra
     * character, C string nul termination, even though SSID is
     * really an octet string that should not be presented as a C
     * string. Some Linux drivers decrement the length by one and
     * can thus end up missing the last octet of the SSID if the
     * length is not incremented here. WE-21 changes this to
     * explicitly require the length _not_ to include nul
     * termination. */
    if (ssid_len)
        ssid_len++;
    }
    iwr.u.essid.length = ssid_len;

    if (ioctl(drv->ioctl_sock, SIOCSIWESSID, &iwr) < 0) {
    wpa_printf(MSG_DEBUG, "command did not succeed");
    perror("ioctl[SIOCSIWESSID]");
    ret = -1;
    }

    return ret;
}


/**
 * ar6003_driver_set_freq - Set frequency/channel, SIOCSIWFREQ
 * @priv: Pointer to private data from ar6003_driver_init()
 * @freq: Frequency in MHz
 * Returns: 0 on success, -1 on failure
 */
int ar6003_driver_set_freq(void *priv, int freq)
{
    struct ar6003_driver_data *drv = priv;
    struct iwreq iwr;
    int ret = 0;

    wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);
    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.freq.m = freq * 100000;
    iwr.u.freq.e = 1;

    if (ioctl(drv->ioctl_sock, SIOCSIWFREQ, &iwr) < 0) {
    perror("ioctl[SIOCSIWFREQ]");
    ret = -1;
    }

    return ret;
}

#ifdef CONFIG_P2P
static void ar6003_driver_p2p_group_frm_status(void *ctx, void *res)
{
    WMI_P2P_GO_NEG_RESULT_EVENT *neg_res;
    struct p2p_go_neg_results *p2p_res;
    union wpa_event_data event;

    wpa_printf(MSG_DEBUG, "%s", __func__);

    wpa_hexdump(MSG_DEBUG,"GO dump after",(u8*)res,64);
    neg_res= (WMI_P2P_GO_NEG_RESULT_EVENT *)res; 
    p2p_res = (struct p2p_go_neg_results *)os_malloc(sizeof(struct p2p_go_neg_results));
    os_memset(&event, 0, sizeof(event));
    os_memset(p2p_res, 0, sizeof(struct p2p_go_neg_results));

    p2p_res->freq = neg_res->freq;
    p2p_res->status = neg_res->status;
    p2p_res->role_go = neg_res->role_go;
    p2p_res->ssid_len = neg_res->ssid_len;
    p2p_res->wps_method = neg_res->wps_method;
    os_memcpy(p2p_res->peer_device_addr, neg_res->peer_device_addr, ETH_ALEN);
    os_memcpy(p2p_res->peer_interface_addr, neg_res->peer_interface_addr, ETH_ALEN);
    os_memcpy(p2p_res->ssid, neg_res->ssid, neg_res->ssid_len);
    os_memcpy(p2p_res->passphrase, neg_res->pass_phrase, 8); 
       
    event.p2p_go_neg_completed.res = p2p_res;
    wpa_supplicant_event(ctx, EVENT_P2P_GO_NEG_COMPLETED, &event);
}

static void ar6003_driver_p2p_invite_sent_status(void *ctx,
           WMI_P2P_INVITE_SENT_RESULT_EVENT *inv_sent_result)
{
    union wpa_event_data event;

    wpa_printf(MSG_DEBUG, "%s", __func__);
    wpa_hexdump(MSG_DEBUG,"Invitation Sent Result",(u8*)inv_sent_result,10);

    os_memset(&event, 0, sizeof(event));
    event.p2p_invite_sent_result.status = inv_sent_result->status;
    event.p2p_invite_sent_result.bssid = inv_sent_result->bssid;

    wpa_supplicant_event(ctx, EVENT_P2P_INVITATION_SENT_RESULT, &event);
}

static void ar6003_driver_p2p_invite_rcvd_status(void *ctx,
           WMI_P2P_INVITE_RCVD_RESULT_EVENT *inv_rcvd_result)
{
    union wpa_event_data event;

    wpa_printf(MSG_DEBUG, "%s", __func__);
    wpa_hexdump(MSG_DEBUG,"Invitation Received Result",(u8*)inv_rcvd_result,60);

    os_memset(&event, 0, sizeof(event));
    event.p2p_invite_rcvd_result.sa = inv_rcvd_result->sa;
    event.p2p_invite_rcvd_result.bssid = inv_rcvd_result->bssid;
    event.p2p_invite_rcvd_result.ssid = inv_rcvd_result->ssid.ssid;
    event.p2p_invite_rcvd_result.ssid_len = inv_rcvd_result->ssid.ssidLength;
    event.p2p_invite_rcvd_result.go_dev_addr = inv_rcvd_result->go_dev_addr;
    event.p2p_invite_rcvd_result.status= inv_rcvd_result->status;
    event.p2p_invite_rcvd_result.op_freq = inv_rcvd_result->oper_freq;

    wpa_supplicant_event(ctx, EVENT_P2P_INVITATION_RCVD_RESULT, &event);
}

static void ar6003_driver_p2p_prov_disc_req(void *ctx, char *prov_disc_req)
{
    union wpa_event_data event;
    char *pos = prov_disc_req;

    wpa_printf(MSG_DEBUG, "%s", __func__);
    wpa_hexdump(MSG_DEBUG,"P2P Prov Disc Req",(u8*)prov_disc_req,60);

    os_memset(&event, 0, sizeof(event));

    event.p2p_prov_disc_req.peer = (u8 *)pos;
    pos += ETH_ALEN;
    event.p2p_prov_disc_req.dev_addr = (u8 *)pos;
    pos += ETH_ALEN;
    event.p2p_prov_disc_req.pri_dev_type = (u8 *)pos;
    pos += 8; // 8 byte pri_dev_type
    event.p2p_prov_disc_req.dev_name = pos;
    while (*pos != '\0') {
    pos++;
    }
    pos++;

    event.p2p_prov_disc_req.supp_config_methods = (*(u16 *)(pos));
    pos += 2;

    event.p2p_prov_disc_req.config_methods = (*(u16 *)(pos));
    pos += 2;

    event.p2p_prov_disc_req.dev_capab = (*(u8 *)(pos));
    pos++;
    event.p2p_prov_disc_req.group_capab = (*(u8 *)(pos));

    wpa_supplicant_event(ctx, EVENT_P2P_PROV_DISC_REQUEST, &event);
}

static void ar6003_driver_p2p_prov_disc_resp(void *ctx, char *prov_disc_resp)
{
    union wpa_event_data event;
    char *pos = prov_disc_resp;

    wpa_printf(MSG_DEBUG, "%s", __func__);
    wpa_hexdump(MSG_DEBUG,"P2P Device Found",(u8*)prov_disc_resp,8);

    os_memset(&event, 0, sizeof(event));
    event.p2p_prov_disc_resp.peer = (u8 *)pos;
    pos += ETH_ALEN;

    event.p2p_prov_disc_resp.config_methods = (*(u16 *)(pos));
    pos += 2;

    wpa_supplicant_event(ctx, EVENT_P2P_PROV_DISC_RESPONSE, &event);
}

static void ar6003_driver_p2p_dev_found(void *ctx, char *p2p_dev_found_ev)
{
    union wpa_event_data event;
    char *pos = p2p_dev_found_ev;

    wpa_printf(MSG_DEBUG, "%s", __func__);
    wpa_hexdump(MSG_DEBUG,"P2P Device Found",(u8*)p2p_dev_found_ev,40);

    os_memset(&event, 0, sizeof(event));
    event.p2p_dev_found.addr = (u8 *)pos;
    pos += ETH_ALEN;
    event.p2p_dev_found.dev_addr = (u8 *)pos;
    pos += ETH_ALEN;
    event.p2p_dev_found.pri_dev_type = (u8 *)pos;
    pos += 8; // 8 byte pri_dev_type
    event.p2p_dev_found.dev_name = pos;
    while (*pos != '\0') {
    pos++;
    }
    pos++;

    event.p2p_dev_found.config_methods = (*(u16 *)(pos));
    pos += 2;
    event.p2p_dev_found.dev_capab = (*(u8 *)(pos));
    pos++;
    event.p2p_dev_found.group_capab = (*(u8 *)(pos));

    wpa_supplicant_event(ctx, EVENT_P2P_DEV_FOUND, &event);
}
#endif

static void
ar6003_driver_event_wireless_custom(void *ctx, char *custom)
{
    union wpa_event_data data;

    wpa_printf(MSG_MSGDUMP, "Custom wireless event: '%s'",
       custom);

    os_memset(&data, 0, sizeof(data));
    /* Host AP driver */
    if (os_strncmp(custom, "MLME-MICHAELMICFAILURE.indication", 33) == 0) {
    data.michael_mic_failure.unicast =
        os_strstr(custom, " unicast ") != NULL;
    /* TODO: parse parameters(?) */
    wpa_supplicant_event(ctx, EVENT_MICHAEL_MIC_FAILURE, &data);
    } else if (os_strncmp(custom, "ASSOCINFO(ReqIEs=", 17) == 0) {
    char *spos;
    int bytes;
    u8 *req_ies = NULL, *resp_ies = NULL;

    spos = custom + 17;

    bytes = strspn(spos, "0123456789abcdefABCDEF");
    if (!bytes || (bytes & 1))
        return;
    bytes /= 2;

    req_ies = os_malloc(bytes);
    if (req_ies == NULL ||
        hexstr2bin(spos, req_ies, bytes) < 0)
        goto done;
    data.assoc_info.req_ies = req_ies;
    data.assoc_info.req_ies_len = bytes;

    spos += bytes * 2;

    data.assoc_info.resp_ies = NULL;
    data.assoc_info.resp_ies_len = 0;

    if (os_strncmp(spos, " RespIEs=", 9) == 0) {
        spos += 9;

        bytes = strspn(spos, "0123456789abcdefABCDEF");
        if (!bytes || (bytes & 1))
            goto done;
        bytes /= 2;

        resp_ies = os_malloc(bytes);
        if (resp_ies == NULL ||
            hexstr2bin(spos, resp_ies, bytes) < 0)
            goto done;
        data.assoc_info.resp_ies = resp_ies;
        data.assoc_info.resp_ies_len = bytes;
    }

    wpa_supplicant_event(ctx, EVENT_ASSOCINFO, &data);

    done:
    os_free(resp_ies);
    os_free(req_ies);
#ifdef CONFIG_PEERKEY
    } else if (os_strncmp(custom, "STKSTART.request=", 17) == 0) {
    if (hwaddr_aton(custom + 17, data.stkstart.peer)) {
        wpa_printf(MSG_DEBUG, "unrecognized "
               "STKSTART.request '%s'", custom + 17);
        return;
    }
    wpa_supplicant_event(ctx, EVENT_STKSTART, &data);
#endif /* CONFIG_PEERKEY */
#ifdef CONFIG_P2P
    } else if (os_strncmp(custom, "P2PNEGCOMPLETE", 14 )==0) {
    p2p_state = P2PNEGOCOMPLETE;
    WMI_P2P_GO_NEG_RESULT_EVENT *p2pneg_res;
    p2pneg_res = (WMI_P2P_GO_NEG_RESULT_EVENT *)(custom+14);
    ar6003_driver_p2p_group_frm_status(ctx, p2pneg_res); 
    } else if (os_strncmp(custom, "P2PINVITESENTRESULT", 19) == 0) {
    WMI_P2P_INVITE_SENT_RESULT_EVENT *inv_sent_result;
    inv_sent_result = (WMI_P2P_INVITE_SENT_RESULT_EVENT *)(custom+19);
    ar6003_driver_p2p_invite_sent_status(ctx, inv_sent_result);
    } else if (os_strncmp(custom, "P2PINVITERCVDRESULT", 19) == 0) {
    WMI_P2P_INVITE_RCVD_RESULT_EVENT *inv_rcvd_result;
    inv_rcvd_result = (WMI_P2P_INVITE_RCVD_RESULT_EVENT *)(custom+19);
    ar6003_driver_p2p_invite_rcvd_status(ctx, inv_rcvd_result);
    } else if (os_strncmp(custom, "P2PDEVFOUND", 11) == 0) {
    ar6003_driver_p2p_dev_found(ctx, custom+11);
    } else if (os_strncmp(custom, "P2PPROVDISCREQ", 14) == 0) {
    ar6003_driver_p2p_prov_disc_req(ctx, custom+14);
    } else if (os_strncmp(custom, "P2PPROVDISCRESP", 15) == 0) {
    ar6003_driver_p2p_prov_disc_resp(ctx, custom+15);
#endif /* CONFIG_P2P */
    }
}


static int ar6003_driver_event_wireless_michaelmicfailure(
    void *ctx, const char *ev, size_t len)
{
    const struct iw_michaelmicfailure *mic;
    union wpa_event_data data;

    if (len < sizeof(*mic))
    return -1;

    mic = (const struct iw_michaelmicfailure *) ev;

    wpa_printf(MSG_DEBUG, "Michael MIC failure wireless event: "
       "flags=0x%x src_addr=" MACSTR, mic->flags,
       MAC2STR(mic->src_addr.sa_data));

    os_memset(&data, 0, sizeof(data));
    data.michael_mic_failure.unicast = !(mic->flags & IW_MICFAILURE_GROUP);
    wpa_supplicant_event(ctx, EVENT_MICHAEL_MIC_FAILURE, &data);

    return 0;
}


static int ar6003_driver_event_wireless_pmkidcand(
    struct ar6003_driver_data *drv, const char *ev, size_t len)
{
    const struct iw_pmkid_cand *cand;
    union wpa_event_data data;
    const u8 *addr;

    if (len < sizeof(*cand))
    return -1;

    cand = (const struct iw_pmkid_cand *) ev;
    addr = (const u8 *) cand->bssid.sa_data;

    wpa_printf(MSG_DEBUG, "PMKID candidate wireless event: "
       "flags=0x%x index=%d bssid=" MACSTR, cand->flags,
       cand->index, MAC2STR(addr));

    os_memset(&data, 0, sizeof(data));
    os_memcpy(data.pmkid_candidate.bssid, addr, ETH_ALEN);
    data.pmkid_candidate.index = cand->index;
    data.pmkid_candidate.preauth = cand->flags & IW_PMKID_CAND_PREAUTH;
    wpa_supplicant_event(drv->ctx, EVENT_PMKID_CANDIDATE, &data);

    return 0;
}


static int ar6003_driver_event_wireless_assocreqie(
    struct ar6003_driver_data *drv, const char *ev, int len)
{
    if (len < 0)
    return -1;

    wpa_hexdump(MSG_DEBUG, "AssocReq IE wireless event", (const u8 *) ev,
        len);
    os_free(drv->assoc_req_ies);
    drv->assoc_req_ies = os_malloc(len);
    if (drv->assoc_req_ies == NULL) {
    drv->assoc_req_ies_len = 0;
    return -1;
    }
    os_memcpy(drv->assoc_req_ies, ev, len);
    drv->assoc_req_ies_len = len;

    return 0;
}


static int ar6003_driver_event_wireless_assocrespie(
    struct ar6003_driver_data *drv, const char *ev, int len)
{
    if (len < 0)
    return -1;

    wpa_hexdump(MSG_DEBUG, "AssocResp IE wireless event", (const u8 *) ev,
        len);
    os_free(drv->assoc_resp_ies);
    drv->assoc_resp_ies = os_malloc(len);
    if (drv->assoc_resp_ies == NULL) {
    drv->assoc_resp_ies_len = 0;
    return -1;
    }
    os_memcpy(drv->assoc_resp_ies, ev, len);
    drv->assoc_resp_ies_len = len;

    return 0;
}


static void ar6003_driver_event_assoc_ies(struct ar6003_driver_data *drv)
{
    union wpa_event_data data;

    if (drv->assoc_req_ies == NULL && drv->assoc_resp_ies == NULL)
    return;

    os_memset(&data, 0, sizeof(data));
    if (drv->assoc_req_ies) {
    data.assoc_info.req_ies = drv->assoc_req_ies;
    data.assoc_info.req_ies_len = drv->assoc_req_ies_len;
    }
    if (drv->assoc_resp_ies) {
    data.assoc_info.resp_ies = drv->assoc_resp_ies;
    data.assoc_info.resp_ies_len = drv->assoc_resp_ies_len;
    }

    wpa_supplicant_event(drv->ctx, EVENT_ASSOCINFO, &data);

    os_free(drv->assoc_req_ies);
    drv->assoc_req_ies = NULL;
    os_free(drv->assoc_resp_ies);
    drv->assoc_resp_ies = NULL;
}


static void ar6003_driver_ap_event_assoc(struct ar6003_driver_data *drv, u8 addr[ATH_MAC_LEN])
{
    union wpa_event_data data;
    struct ieee80211req_wpaie *ie;


    u8 buf[528]; 
    u8 *iebuf;
    /*
     * Fetch negotiated WPA/RSN parameters from the system.
     */
     memset(buf, 0, sizeof(buf));
     ((int *)buf)[0] = IEEE80211_IOCTL_GETWPAIE;
     ie = (struct ieee80211req_wpaie *)&buf[4];
     memcpy(ie->wpa_macaddr, addr, IEEE80211_ADDR_LEN);

     if (set80211priv(drv, AR6000_IOCTL_EXTENDED, buf, sizeof(*ie)+4)) {
          wpa_printf(MSG_ERROR, "%s: Failed to get WPA/RSN IE",
           __func__);
          printf("Failed to get WPA/RSN information element.\n");
          goto no_ie;
      }
      ie = (struct ieee80211req_wpaie *)&buf[4];
      iebuf = ie->wpa_ie;    
      os_memset(&data, 0, sizeof(data));
      data.assoc_info.req_ies = ie->wpa_ie;
      data.assoc_info.req_ies_len = iebuf[1];
      if(data.assoc_info.req_ies_len == 0)
            data.assoc_info.req_ies_len =0;
      else
            data.assoc_info.req_ies_len +=2;
no_ie:
      data.assoc_info.addr = addr; 
      wpa_supplicant_event(drv->ctx, EVENT_ASSOC, &data);

}

static void ar6003_driver_ap_event_disassoc(struct ar6003_driver_data *drv, u8 addr[ATH_MAC_LEN])
{
    union wpa_event_data data;


    os_memset(&data, 0, sizeof(data));

    data.disassoc_info.addr = addr; 
    wpa_supplicant_event(drv->ctx, EVENT_DISASSOC, &data);

}
static void ar6003_driver_event_wireless(struct ar6003_driver_data *drv,
                   char *data, int len)
{
    struct iw_event iwe_buf, *iwe = &iwe_buf;
    char *pos, *end, *custom, *buf;

    pos = data;
    end = data + len;

    while (pos + IW_EV_LCP_LEN <= end) {
    /* Event data may be unaligned, so make a local, aligned copy
     * before processing. */
    os_memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);
    wpa_printf(MSG_DEBUG, "Wireless event: cmd=0x%x len=%d",
           iwe->cmd, iwe->len);
    if (iwe->len <= IW_EV_LCP_LEN)
        return;

    custom = pos + IW_EV_POINT_LEN;
    if (drv->we_version_compiled > 18 &&
        (iwe->cmd == IWEVMICHAELMICFAILURE ||
         iwe->cmd == IWEVCUSTOM ||
         iwe->cmd == IWEVASSOCREQIE ||
         iwe->cmd == IWEVASSOCRESPIE ||
         iwe->cmd == IWEVPMKIDCAND)) {
        /* WE-19 removed the pointer from struct iw_point */
        char *dpos = (char *) &iwe_buf.u.data.length;
        int dlen = dpos - (char *) &iwe_buf;
        os_memcpy(dpos, pos + IW_EV_LCP_LEN,
              sizeof(struct iw_event) - dlen);
    } else {
        os_memcpy(&iwe_buf, pos, sizeof(struct iw_event));
        custom += IW_EV_POINT_OFF;
    }

    switch (iwe->cmd) {
    case SIOCGIWAP:
        wpa_printf(MSG_DEBUG, "Wireless event: new AP: "
               MACSTR,
               MAC2STR((u8 *) iwe->u.ap_addr.sa_data));
        if (is_zero_ether_addr(
                (const u8 *) iwe->u.ap_addr.sa_data) ||
            os_memcmp(iwe->u.ap_addr.sa_data,
                  "\x44\x44\x44\x44\x44\x44", ETH_ALEN) ==
            0) {
            os_free(drv->assoc_req_ies);
            drv->assoc_req_ies = NULL;
            os_free(drv->assoc_resp_ies);
            drv->assoc_resp_ies = NULL;
            wpa_supplicant_event(drv->ctx, EVENT_DISASSOC,
                         NULL);
        
        } else {
            ar6003_driver_event_assoc_ies(drv);
            wpa_supplicant_event(drv->ctx, EVENT_ASSOC,
                         NULL);
        }
        break;
    case IWEVMICHAELMICFAILURE:
        if (custom + iwe->u.data.length > end) {
            wpa_printf(MSG_DEBUG, "Invalid "
                   "IWEVMICHAELMICFAILURE length");
            return;
        }
        ar6003_driver_event_wireless_michaelmicfailure(
            drv->ctx, custom, iwe->u.data.length);
        break;
    case IWEVCUSTOM:
        if (custom + iwe->u.data.length > end) {
            wpa_printf(MSG_DEBUG, "Invalid "
                   "IWEVCUSTOM length");
            return;
        }
        buf = os_malloc(iwe->u.data.length + 1);
        if (buf == NULL)
            return;
        os_memcpy(buf, custom, iwe->u.data.length);
        buf[iwe->u.data.length] = '\0';
        ar6003_driver_event_wireless_custom(drv->ctx, buf);
        os_free(buf);
        break;
    case SIOCGIWSCAN:
        drv->scan_complete_events = 1;
        eloop_cancel_timeout(ar6003_driver_scan_timeout,
                     drv, drv->ctx);
        wpa_supplicant_event(drv->ctx, EVENT_SCAN_RESULTS,
                     NULL);
        break;
    case IWEVASSOCREQIE:
        if (custom + iwe->u.data.length > end) {
            wpa_printf(MSG_DEBUG, "Invalid "
                   "IWEVASSOCREQIE length");
            return;
        }
        ar6003_driver_event_wireless_assocreqie(
            drv, custom, iwe->u.data.length);
        break;
    case IWEVASSOCRESPIE:
        if (custom + iwe->u.data.length > end) {
            wpa_printf(MSG_DEBUG, "Invalid "
                   "IWEVASSOCRESPIE length");
            return;
        }
        ar6003_driver_event_wireless_assocrespie(
            drv, custom, iwe->u.data.length);
        break;
    case IWEVPMKIDCAND:
        if (custom + iwe->u.data.length > end) {
            wpa_printf(MSG_DEBUG, "Invalid "
                   "IWEVPMKIDCAND length");
            return;
        }
        ar6003_driver_event_wireless_pmkidcand(
            drv, custom, iwe->u.data.length);
        break;
            case IWEVEXPIRED:
                    ar6003_driver_ap_event_disassoc(drv, (u8 *) iwe->u.addr.sa_data);
                    break;
            case IWEVREGISTERED:
                    ar6003_driver_ap_event_assoc(drv, (u8 *) iwe->u.addr.sa_data);
                    break;
    }

    pos += iwe->len;
    }
}


static void ar6003_driver_event_link(struct ar6003_driver_data *drv,
                   char *buf, size_t len, int del)
{
    union wpa_event_data event;

    os_memset(&event, 0, sizeof(event));
    if (len > sizeof(event.interface_status.ifname))
    len = sizeof(event.interface_status.ifname) - 1;
    os_memcpy(event.interface_status.ifname, buf, len);
    event.interface_status.ievent = del ? EVENT_INTERFACE_REMOVED :
    EVENT_INTERFACE_ADDED;

    wpa_printf(MSG_DEBUG, "RTM_%sLINK, IFLA_IFNAME: Interface '%s' %s",
       del ? "DEL" : "NEW",
       event.interface_status.ifname,
       del ? "removed" : "added");

    if (os_strcmp(drv->ifname, event.interface_status.ifname) == 0) {
    if (del)
        drv->if_removed = 1;
    else
        drv->if_removed = 0;
    }

    wpa_supplicant_event(drv->ctx, EVENT_INTERFACE_STATUS, &event);
}


static int ar6003_driver_own_ifname(struct ar6003_driver_data *drv,
                  u8 *buf, size_t len)
{
    int attrlen, rta_len;
    struct rtattr *attr;

    attrlen = len;
    attr = (struct rtattr *) buf;

    rta_len = RTA_ALIGN(sizeof(struct rtattr));
    while (RTA_OK(attr, attrlen)) {
    if (attr->rta_type == IFLA_IFNAME) {
        if (os_strcmp(((char *) attr) + rta_len, drv->ifname)
            == 0)
            return 1;
        else
            break;
    }
    attr = RTA_NEXT(attr, attrlen);
    }

    return 0;
}


static int ar6003_driver_own_ifindex(struct ar6003_driver_data *drv,
                   int ifindex, u8 *buf, size_t len)
{
    if (drv->ifindex == ifindex || drv->ifindex2 == ifindex)
    return 1;

    if (drv->if_removed && ar6003_driver_own_ifname(drv, buf, len)) {
    drv->ifindex = if_nametoindex(drv->ifname);
    wpa_printf(MSG_DEBUG, "Update ifindex for a removed "
           "interface");
    ar6003_driver_finish_drv_init(drv);
    return 1;
    }

    return 0;
}


static void ar6003_driver_event_rtm_newlink(void *ctx, struct ifinfomsg *ifi,
                      u8 *buf, size_t len)
{
    struct ar6003_driver_data *drv = ctx;
    int attrlen, rta_len;
    struct rtattr *attr;

    if (!ar6003_driver_own_ifindex(drv, ifi->ifi_index, buf, len)) {
    wpa_printf(MSG_DEBUG, "Ignore event for foreign ifindex %d",
           ifi->ifi_index);
    return;
    }

    wpa_printf(MSG_DEBUG, "RTM_NEWLINK: operstate=%d ifi_flags=0x%x "
       "(%s%s%s%s)",
       drv->operstate, ifi->ifi_flags,
       (ifi->ifi_flags & IFF_UP) ? "[UP]" : "",
       (ifi->ifi_flags & IFF_RUNNING) ? "[RUNNING]" : "",
       (ifi->ifi_flags & IFF_LOWER_UP) ? "[LOWER_UP]" : "",
       (ifi->ifi_flags & IFF_DORMANT) ? "[DORMANT]" : "");
    /*
     * Some drivers send the association event before the operup event--in
     * this case, lifting operstate in ar6003_driver_set_operstate()
     * fails. This will hit us when wpa_supplicant does not need to do
     * IEEE 802.1X authentication
     */
    if (drv->operstate == 1 &&
    (ifi->ifi_flags & (IFF_LOWER_UP | IFF_DORMANT)) == IFF_LOWER_UP &&
    !(ifi->ifi_flags & IFF_RUNNING))
    netlink_send_oper_ifla(drv->netlink, drv->ifindex,
                   -1, IF_OPER_UP);

    attrlen = len;
    attr = (struct rtattr *) buf;

    rta_len = RTA_ALIGN(sizeof(struct rtattr));
    while (RTA_OK(attr, attrlen)) {
    if (attr->rta_type == IFLA_WIRELESS) {
        ar6003_driver_event_wireless(
            drv, ((char *) attr) + rta_len,
            attr->rta_len - rta_len);
    } else if (attr->rta_type == IFLA_IFNAME) {
        ar6003_driver_event_link(drv,
                       ((char *) attr) + rta_len,
                       attr->rta_len - rta_len, 0);
    }
    attr = RTA_NEXT(attr, attrlen);
    }
}


static void ar6003_driver_event_rtm_dellink(void *ctx, struct ifinfomsg *ifi,
                      u8 *buf, size_t len)
{
    struct ar6003_driver_data *drv = ctx;
    int attrlen, rta_len;
    struct rtattr *attr;

    attrlen = len;
    attr = (struct rtattr *) buf;

    rta_len = RTA_ALIGN(sizeof(struct rtattr));
    while (RTA_OK(attr, attrlen)) {
    if (attr->rta_type == IFLA_IFNAME) {
        ar6003_driver_event_link(drv,
                       ((char *) attr) + rta_len,
                       attr->rta_len - rta_len, 1);
    }
    attr = RTA_NEXT(attr, attrlen);
    }
}

static void
handle_read(void *ctx, const u8 *src_addr, const u8 *buf, size_t len)
{
    struct ar6003_driver_data *drv = ctx;
    union wpa_event_data data;
    os_memset(&data, 0, sizeof(data));

    data.eapol_rx.src = src_addr;
    data.eapol_rx.data = buf;
    data.eapol_rx.data_len = len;
    wpa_supplicant_event(drv->ctx, EVENT_EAPOL_RX, &data);
}

/**
 * ar6003_driver_init - Initialize WE driver interface
 * @ctx: context to be used when calling wpa_supplicant functions,
 * e.g., wpa_supplicant_event()
 * @ifname: interface name, e.g., wlan0
 * Returns: Pointer to private data, %NULL on failure
 */
void * ar6003_driver_init(void *ctx, const char *ifname)
{
    struct ar6003_driver_data *drv;
    struct netlink_config *cfg;
    char path[128];
    struct stat buf;

    drv = os_zalloc(sizeof(*drv));
    if (drv == NULL)
    return NULL;
    drv->ctx = ctx;
    os_strlcpy(drv->ifname, ifname, sizeof(drv->ifname));

    os_snprintf(path, sizeof(path), "/sys/class/net/%s/phy80211", ifname);
    if (stat(path, &buf) == 0) {
    wpa_printf(MSG_DEBUG, "cfg80211-based driver detected");
    drv->cfg80211 = 1;
    }

    drv->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (drv->ioctl_sock < 0) {
    perror("socket(PF_INET,SOCK_DGRAM)");
    goto err1;
    }

    cfg = os_zalloc(sizeof(*cfg));
    if (cfg == NULL)
    goto err1;
    cfg->ctx = drv;
    cfg->newlink_cb = ar6003_driver_event_rtm_newlink;
    cfg->dellink_cb = ar6003_driver_event_rtm_dellink;
    drv->netlink = netlink_init(cfg);
    if (drv->netlink == NULL) {
    os_free(cfg);
    goto err2;
    }

    drv->mlme_sock = -1;

    if (ar6003_driver_finish_drv_init(drv) < 0)
    goto err3;

    ar6003_driver_set_auth_param(drv, IW_AUTH_WPA_ENABLED, 1);
    
    drv->capa.flags |= (WPA_DRIVER_FLAGS_P2P_MGMT | WPA_DRIVER_FLAGS_P2P_CAPABLE);

    drv->sock_xmit = l2_packet_init(drv->ifname, NULL, ETH_P_EAPOL,
                     handle_read, drv, 1);
    if (drv->sock_xmit == NULL)
           goto err3;
    drv->sock_recv = drv->sock_xmit;

    return drv;

err3:
    netlink_deinit(drv->netlink);
err2:
    close(drv->ioctl_sock);
err1:
    os_free(drv);
    return NULL;
}


static int ar6003_driver_finish_drv_init(struct ar6003_driver_data *drv)
{
    if (linux_set_iface_flags(drv->ioctl_sock, drv->ifname, 1) < 0)
    return -1;

    /*
     * Make sure that the driver does not have any obsolete PMKID entries.
     */
    ar6003_driver_flush_pmkid(drv);

    if (ar6003_driver_set_mode(drv, 0) < 0) {
    wpa_printf(MSG_DEBUG, "Could not configure driver to use "
           "managed mode");
    /* Try to use it anyway */
    }

    ar6003_driver_get_range(drv);

    /*
     * Unlock the driver's BSSID and force to a random SSID to clear any
     * previous association the driver might have when the supplicant
     * starts up.
     */
//    ar6003_driver_disconnect(drv);

    drv->ifindex = if_nametoindex(drv->ifname);

    if (os_strncmp(drv->ifname, "wlan", 4) == 0) {
    /*
     * Host AP driver may use both wlan# and wifi# interface in
     * wireless events. Since some of the versions included WE-18
     * support, let's add the alternative ifindex also from
     * driver_wext.c for the time being. This may be removed at
     * some point once it is believed that old versions of the
     * driver are not in use anymore.
     */
    char ifname2[IFNAMSIZ + 1];
    os_strlcpy(ifname2, drv->ifname, sizeof(ifname2));
    os_memcpy(ifname2, "wifi", 4);
    ar6003_driver_alternative_ifindex(drv, ifname2);
    }

    if (ar6003_driver_capa(drv))
               return -1;
    netlink_send_oper_ifla(drv->netlink, drv->ifindex,
               1, IF_OPER_DORMANT);

    return 0;
}


/**
 * ar6003_driver_deinit - Deinitialize WE driver interface
 * @priv: Pointer to private data from ar6003_driver_init()
 *
 * Shut down driver interface and processing of driver events. Free
 * private data buffer if one was allocated in ar6003_driver_init().
 */
void ar6003_driver_deinit(void *priv)
{
    struct ar6003_driver_data *drv = priv;

    ar6003_driver_set_auth_param(drv, IW_AUTH_WPA_ENABLED, 0);

    eloop_cancel_timeout(ar6003_driver_scan_timeout, drv, drv->ctx);

    /*
     * Clear possibly configured driver parameters in order to make it
     * easier to use the driver after wpa_supplicant has been terminated.
     */
    ar6003_driver_disconnect(drv);

    netlink_send_oper_ifla(drv->netlink, drv->ifindex, 0, IF_OPER_UP);
    netlink_deinit(drv->netlink);

    if (drv->mlme_sock >= 0)
    eloop_unregister_read_sock(drv->mlme_sock);

    ar6003_wireless_event_deinit(priv);

    (void) linux_set_iface_flags(drv->ioctl_sock, drv->ifname, 0);

    close(drv->ioctl_sock);
    if (drv->mlme_sock >= 0)
    close(drv->mlme_sock);
    os_free(drv->assoc_req_ies);
    os_free(drv->assoc_resp_ies);
    os_free(drv);
}


/**
 * ar6003_driver_scan_timeout - Scan timeout to report scan completion
 * @eloop_ctx: Unused
 * @timeout_ctx: ctx argument given to ar6003_driver_init()
 *
 * This function can be used as registered timeout when starting a scan to
 * generate a scan completed event if the driver does not report this.
 */
void ar6003_driver_scan_timeout(void *eloop_ctx, void *timeout_ctx)
{
    wpa_printf(MSG_DEBUG, "Scan timeout - try to get results");
    wpa_supplicant_event(timeout_ctx, EVENT_SCAN_RESULTS, NULL);
}


/**
 * ar6003_driver_scan - Request the driver to initiate scan
 * @priv: Pointer to private data from ar6003_driver_init()
 * @param: Scan parameters (specific SSID to scan for (ProbeReq), etc.)
 * Returns: 0 on success, -1 on failure
 */
int ar6003_driver_scan(void *priv, struct wpa_driver_scan_params *params)
{
    struct ar6003_driver_data *drv = priv;
    struct iwreq iwr;
    int ret = 0, timeout;
    struct iw_scan_req req;
    const u8 *ssid = params->ssids[0].ssid;
    size_t ssid_len = params->ssids[0].ssid_len;
    unsigned int ctr;

    if(p2p_state != P2PNEGOCOMPLETE)
    return -1;

    if (ssid_len > IW_ESSID_MAX_SIZE) {
    wpa_printf(MSG_DEBUG, "%s: too long SSID (%lu)",
           __FUNCTION__, (unsigned long) ssid_len);
    return -1;
    }

    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);

    os_memset(&req, 0, sizeof(req));

    if (ssid && ssid_len) {
    req.essid_len = ssid_len;
    req.bssid.sa_family = ARPHRD_ETHER;
    os_memset(req.bssid.sa_data, 0xff, ETH_ALEN);
    os_memcpy(req.essid, ssid, ssid_len);
    iwr.u.data.flags = IW_SCAN_THIS_ESSID;
    }

    if (params->freqs) {
    for (ctr=0; params->freqs[ctr] != 0; ctr++) {
        req.channel_list[ctr].m = params->freqs[ctr];
    }
    req.num_channels = ctr;
    iwr.u.data.flags |= IW_SCAN_THIS_FREQ;
    }

    iwr.u.data.pointer = (caddr_t) &req;
    iwr.u.data.length = sizeof(req);

    if (ioctl(drv->ioctl_sock, SIOCSIWSCAN, &iwr) < 0) {
    perror("ioctl[SIOCSIWSCAN]");
    ret = -1;
    }

    /* Not all drivers generate "scan completed" wireless event, so try to
     * read results after a timeout. */
    timeout = 5;
    if (drv->scan_complete_events) {
    /*
     * The driver seems to deliver SIOCGIWSCAN events to notify
     * when scan is complete, so use longer timeout to avoid race
     * conditions with scanning and following association request.
     */
    timeout = 30;
    }
    wpa_printf(MSG_DEBUG, "Scan requested (ret=%d) - scan timeout %d "
       "seconds", ret, timeout);
    eloop_cancel_timeout(ar6003_driver_scan_timeout, drv, drv->ctx);
    eloop_register_timeout(timeout, 0, ar6003_driver_scan_timeout, drv,
               drv->ctx);

    return ret;
}


static u8 * ar6003_driver_giwscan(struct ar6003_driver_data *drv,
                size_t *len)
{
    struct iwreq iwr;
    u8 *res_buf;
    size_t res_buf_len;

    res_buf_len = IW_SCAN_MAX_DATA;
    for (;;) {
    res_buf = os_malloc(res_buf_len);
    if (res_buf == NULL)
        return NULL;
    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.data.pointer = res_buf;
    iwr.u.data.length = res_buf_len;

    if (ioctl(drv->ioctl_sock, SIOCGIWSCAN, &iwr) == 0)
        break;

    if (errno == E2BIG && res_buf_len < 65535) {
        os_free(res_buf);
        res_buf = NULL;
        res_buf_len *= 2;
        if (res_buf_len > 65535)
            res_buf_len = 65535; /* 16-bit length field */
        wpa_printf(MSG_DEBUG, "Scan results did not fit - "
               "trying larger buffer (%lu bytes)",
               (unsigned long) res_buf_len);
    } else {
        perror("ioctl[SIOCGIWSCAN]");
        os_free(res_buf);
        return NULL;
    }
    }

    if (iwr.u.data.length > res_buf_len) {
    os_free(res_buf);
    return NULL;
    }
    *len = iwr.u.data.length;

    return res_buf;
}


/*
 * Data structure for collecting scan results. This is needed to allow
 * the various methods of reporting IEs to be combined into a single IE buffer.
 */
struct ar6003_scan_data {
    struct wpa_scan_res res;
    u8 *ie;
    size_t ie_len;
    u8 ssid[32];
    size_t ssid_len;
    int maxrate;
};


static void ar6003_get_scan_mode(struct iw_event *iwe,
               struct ar6003_scan_data *res)
{
    if (iwe->u.mode == IW_MODE_ADHOC)
    res->res.caps |= IEEE80211_CAP_IBSS;
    else if (iwe->u.mode == IW_MODE_MASTER || iwe->u.mode == IW_MODE_INFRA)
    res->res.caps |= IEEE80211_CAP_ESS;
}


static void ar6003_get_scan_ssid(struct iw_event *iwe,
               struct ar6003_scan_data *res, char *custom,
               char *end)
{
    int ssid_len = iwe->u.essid.length;
    if (custom + ssid_len > end)
    return;
    if (iwe->u.essid.flags &&
    ssid_len > 0 &&
    ssid_len <= IW_ESSID_MAX_SIZE) {
    os_memcpy(res->ssid, custom, ssid_len);
    res->ssid_len = ssid_len;
    }
}


static void ar6003_get_scan_freq(struct iw_event *iwe,
               struct ar6003_scan_data *res)
{
    int divi = 1000000, i;

    if (iwe->u.freq.e == 0) {
    /*
     * Some drivers do not report frequency, but a channel.
     * Try to map this to frequency by assuming they are using
     * IEEE 802.11b/g.  But don't overwrite a previously parsed
     * frequency if the driver sends both frequency and channel,
     * since the driver may be sending an A-band channel that we
     * don't handle here.
     */

    if (res->res.freq)
        return;

    if (iwe->u.freq.m >= 1 && iwe->u.freq.m <= 13) {
        res->res.freq = 2407 + 5 * iwe->u.freq.m;
        return;
    } else if (iwe->u.freq.m == 14) {
        res->res.freq = 2484;
        return;
    }
    }

    if (iwe->u.freq.e > 6) {
    wpa_printf(MSG_DEBUG, "Invalid freq in scan results (BSSID="
           MACSTR " m=%d e=%d)",
           MAC2STR(res->res.bssid), iwe->u.freq.m,
           iwe->u.freq.e);
    return;
    }

    for (i = 0; i < iwe->u.freq.e; i++)
    divi /= 10;
    res->res.freq = iwe->u.freq.m / divi;
}


static void ar6003_get_scan_qual(struct iw_event *iwe,
               struct ar6003_scan_data *res)
{
    res->res.qual = iwe->u.qual.qual;
    res->res.noise = iwe->u.qual.noise;
    res->res.level = iwe->u.qual.level;
    if (iwe->u.qual.updated & IW_QUAL_QUAL_INVALID)
    res->res.flags |= WPA_SCAN_QUAL_INVALID;
    if (iwe->u.qual.updated & IW_QUAL_LEVEL_INVALID)
    res->res.flags |= WPA_SCAN_LEVEL_INVALID;
    if (iwe->u.qual.updated & IW_QUAL_NOISE_INVALID)
    res->res.flags |= WPA_SCAN_NOISE_INVALID;
    if (iwe->u.qual.updated & IW_QUAL_DBM)
    res->res.flags |= WPA_SCAN_LEVEL_DBM;
}


static void ar6003_get_scan_encode(struct iw_event *iwe,
             struct ar6003_scan_data *res)
{
    if (!(iwe->u.data.flags & IW_ENCODE_DISABLED))
    res->res.caps |= IEEE80211_CAP_PRIVACY;
}


static void ar6003_get_scan_rate(struct iw_event *iwe,
               struct ar6003_scan_data *res, char *pos,
               char *end)
{
    int maxrate;
    char *custom = pos + IW_EV_LCP_LEN;
    struct iw_param p;
    size_t clen;

    clen = iwe->len;
    if (custom + clen > end)
    return;
    maxrate = 0;
    while (((ssize_t) clen) >= (ssize_t) sizeof(struct iw_param)) {
    /* Note: may be misaligned, make a local, aligned copy */
    os_memcpy(&p, custom, sizeof(struct iw_param));
    if (p.value > maxrate)
        maxrate = p.value;
    clen -= sizeof(struct iw_param);
    custom += sizeof(struct iw_param);
    }

    /* Convert the maxrate from WE-style (b/s units) to
     * 802.11 rates (500000 b/s units).
     */
    res->maxrate = maxrate / 500000;
}


static void ar6003_get_scan_iwevgenie(struct iw_event *iwe,
                struct ar6003_scan_data *res, char *custom,
                char *end)
{
    char *genie, *gpos, *gend;
    u8 *tmp;

    if (iwe->u.data.length == 0)
    return;

    gpos = genie = custom;
    gend = genie + iwe->u.data.length;
    if (gend > end) {
    wpa_printf(MSG_INFO, "IWEVGENIE overflow");
    return;
    }

    tmp = os_realloc(res->ie, res->ie_len + gend - gpos);
    if (tmp == NULL)
    return;
    os_memcpy(tmp + res->ie_len, gpos, gend - gpos);
    res->ie = tmp;
    res->ie_len += gend - gpos;
}


static void ar6003_get_scan_custom(struct iw_event *iwe,
             struct ar6003_scan_data *res, char *custom,
             char *end)
{
    size_t clen;
    u8 *tmp;

    clen = iwe->u.data.length;
    if (custom + clen > end)
    return;

    if (clen > 7 && os_strncmp(custom, "wpa_ie=", 7) == 0) {
    char *spos;
    int bytes;
    spos = custom + 7;
    bytes = custom + clen - spos;
    if (bytes & 1 || bytes == 0)
        return;
    bytes /= 2;
    tmp = os_realloc(res->ie, res->ie_len + bytes);
    if (tmp == NULL)
        return;
    res->ie = tmp;
    if (hexstr2bin(spos, tmp + res->ie_len, bytes) < 0)
        return;
    res->ie_len += bytes;
    } else if (clen > 7 && os_strncmp(custom, "rsn_ie=", 7) == 0) {
    char *spos;
    int bytes;
    spos = custom + 7;
    bytes = custom + clen - spos;
    if (bytes & 1 || bytes == 0)
        return;
    bytes /= 2;
    tmp = os_realloc(res->ie, res->ie_len + bytes);
    if (tmp == NULL)
        return;
    res->ie = tmp;
    if (hexstr2bin(spos, tmp + res->ie_len, bytes) < 0)
        return;
    res->ie_len += bytes;
    } else if (clen > 4 && os_strncmp(custom, "tsf=", 4) == 0) {
    char *spos;
    int bytes;
    u8 bin[8];
    spos = custom + 4;
    bytes = custom + clen - spos;
    if (bytes != 16) {
        wpa_printf(MSG_INFO, "Invalid TSF length (%d)", bytes);
        return;
    }
    bytes /= 2;
    if (hexstr2bin(spos, bin, bytes) < 0) {
        wpa_printf(MSG_DEBUG, "Invalid TSF value");
        return;
    }
    res->res.tsf += WPA_GET_BE64(bin);
    }
}


static int ar6003_19_iw_point(struct ar6003_driver_data *drv, u16 cmd)
{
    return drv->we_version_compiled > 18 &&
    (cmd == SIOCGIWESSID || cmd == SIOCGIWENCODE ||
     cmd == IWEVGENIE || cmd == IWEVCUSTOM);
}


static void ar6003_driver_add_scan_entry(struct wpa_scan_results *res,
                   struct ar6003_scan_data *data)
{
    struct wpa_scan_res **tmp;
    struct wpa_scan_res *r;
    size_t extra_len;
    u8 *pos, *end, *ssid_ie = NULL, *rate_ie = NULL;

    /* Figure out whether we need to fake any IEs */
    pos = data->ie;
    end = pos + data->ie_len;
    while (pos && pos + 1 < end) {
    if (pos + 2 + pos[1] > end)
        break;
    if (pos[0] == WLAN_EID_SSID)
        ssid_ie = pos;
    else if (pos[0] == WLAN_EID_SUPP_RATES)
        rate_ie = pos;
    else if (pos[0] == WLAN_EID_EXT_SUPP_RATES)
        rate_ie = pos;
    pos += 2 + pos[1];
    }

    extra_len = 0;
    if (ssid_ie == NULL)
    extra_len += 2 + data->ssid_len;
    if (rate_ie == NULL && data->maxrate)
    extra_len += 3;

    r = os_zalloc(sizeof(*r) + extra_len + data->ie_len);
    if (r == NULL)
    return;
    os_memcpy(r, &data->res, sizeof(*r));
    r->ie_len = extra_len + data->ie_len;
    pos = (u8 *) (r + 1);
    if (ssid_ie == NULL) {
    /*
     * Generate a fake SSID IE since the driver did not report
     * a full IE list.
     */
    *pos++ = WLAN_EID_SSID;
    *pos++ = data->ssid_len;
    os_memcpy(pos, data->ssid, data->ssid_len);
    pos += data->ssid_len;
    }
    if (rate_ie == NULL && data->maxrate) {
    /*
     * Generate a fake Supported Rates IE since the driver did not
     * report a full IE list.
     */
    *pos++ = WLAN_EID_SUPP_RATES;
    *pos++ = 1;
    *pos++ = data->maxrate;
    }
    if (data->ie)
    os_memcpy(pos, data->ie, data->ie_len);

    tmp = os_realloc(res->res,
         (res->num + 1) * sizeof(struct wpa_scan_res *));
    if (tmp == NULL) {
    os_free(r);
    return;
    }
    tmp[res->num++] = r;
    res->res = tmp;
}
                  

/**
 * ar6003_driver_get_scan_results - Fetch the latest scan results
 * @priv: Pointer to private data from ar6003_driver_init()
 * Returns: Scan results on success, -1 on failure
 */
struct wpa_scan_results * ar6003_driver_get_scan_results(void *priv)
{
    struct ar6003_driver_data *drv = priv;
    size_t ap_num = 0, len;
    int first;
    u8 *res_buf;
    struct iw_event iwe_buf, *iwe = &iwe_buf;
    char *pos, *end, *custom;
    struct wpa_scan_results *res;
    struct ar6003_scan_data data;

    res_buf = ar6003_driver_giwscan(drv, &len);
    if (res_buf == NULL)
    return NULL;

    ap_num = 0;
    first = 1;

    res = os_zalloc(sizeof(*res));
    if (res == NULL) {
    os_free(res_buf);
    return NULL;
    }

    pos = (char *) res_buf;
    end = (char *) res_buf + len;
    os_memset(&data, 0, sizeof(data));

    while (pos + IW_EV_LCP_LEN <= end) {
    /* Event data may be unaligned, so make a local, aligned copy
     * before processing. */
    os_memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);
    if (iwe->len <= IW_EV_LCP_LEN)
        break;

    custom = pos + IW_EV_POINT_LEN;
    if (ar6003_19_iw_point(drv, iwe->cmd)) {
        /* WE-19 removed the pointer from struct iw_point */
        char *dpos = (char *) &iwe_buf.u.data.length;
        int dlen = dpos - (char *) &iwe_buf;
        os_memcpy(dpos, pos + IW_EV_LCP_LEN,
              sizeof(struct iw_event) - dlen);
    } else {
        os_memcpy(&iwe_buf, pos, sizeof(struct iw_event));
        custom += IW_EV_POINT_OFF;
    }

    switch (iwe->cmd) {
    case SIOCGIWAP:
        if (!first)
            ar6003_driver_add_scan_entry(res, &data);
        first = 0;
        os_free(data.ie);
        os_memset(&data, 0, sizeof(data));
        os_memcpy(data.res.bssid,
              iwe->u.ap_addr.sa_data, ETH_ALEN);
        break;
    case SIOCGIWMODE:
        ar6003_get_scan_mode(iwe, &data);
        break;
    case SIOCGIWESSID:
        ar6003_get_scan_ssid(iwe, &data, custom, end);
        break;
    case SIOCGIWFREQ:
        ar6003_get_scan_freq(iwe, &data);
        break;
    case IWEVQUAL:
        ar6003_get_scan_qual(iwe, &data);
        break;
    case SIOCGIWENCODE:
        ar6003_get_scan_encode(iwe, &data);
        break;
    case SIOCGIWRATE:
        ar6003_get_scan_rate(iwe, &data, pos, end);
        break;
    case IWEVGENIE:
        ar6003_get_scan_iwevgenie(iwe, &data, custom, end);
        break;
    case IWEVCUSTOM:
        ar6003_get_scan_custom(iwe, &data, custom, end);
        break;
    }

    pos += iwe->len;
    }
    os_free(res_buf);
    res_buf = NULL;
    if (!first)
    ar6003_driver_add_scan_entry(res, &data);
    os_free(data.ie);

    wpa_printf(MSG_DEBUG, "Received %lu bytes of scan results (%lu BSSes)",
       (unsigned long) len, (unsigned long) res->num);

    return res;
}


static int ar6003_driver_get_range(void *priv)
{
    struct ar6003_driver_data *drv = priv;
    struct iw_range *range;
    struct iwreq iwr;
    int minlen;
    size_t buflen;

    /*
     * Use larger buffer than struct iw_range in order to allow the
     * structure to grow in the future.
     */
    buflen = sizeof(struct iw_range) + 500;
    range = os_zalloc(buflen);
    if (range == NULL)
    return -1;

    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.data.pointer = (caddr_t) range;
    iwr.u.data.length = buflen;

    minlen = ((char *) &range->enc_capa) - (char *) range +
    sizeof(range->enc_capa);

    if (ioctl(drv->ioctl_sock, SIOCGIWRANGE, &iwr) < 0) {
    perror("ioctl[SIOCGIWRANGE]");
    os_free(range);
    return -1;
    } else if (iwr.u.data.length >= minlen &&
       range->we_version_compiled >= 18) {
    wpa_printf(MSG_DEBUG, "SIOCGIWRANGE: WE(compiled)=%d "
           "WE(source)=%d enc_capa=0x%x",
           range->we_version_compiled,
           range->we_version_source,
           range->enc_capa);
    drv->has_capability = 1;
    drv->we_version_compiled = range->we_version_compiled;
    if (range->enc_capa & IW_ENC_CAPA_WPA) {
        drv->capa.key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_WPA |
            WPA_DRIVER_CAPA_KEY_MGMT_WPA_PSK;
    }
    if (range->enc_capa & IW_ENC_CAPA_WPA2) {
        drv->capa.key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_WPA2 |
            WPA_DRIVER_CAPA_KEY_MGMT_WPA2_PSK;
    }
    drv->capa.enc |= WPA_DRIVER_CAPA_ENC_WEP40 |
        WPA_DRIVER_CAPA_ENC_WEP104;
    if (range->enc_capa & IW_ENC_CAPA_CIPHER_TKIP)
        drv->capa.enc |= WPA_DRIVER_CAPA_ENC_TKIP;
    if (range->enc_capa & IW_ENC_CAPA_CIPHER_CCMP)
        drv->capa.enc |= WPA_DRIVER_CAPA_ENC_CCMP;
    if (range->enc_capa & IW_ENC_CAPA_4WAY_HANDSHAKE)
        drv->capa.flags |= WPA_DRIVER_FLAGS_4WAY_HANDSHAKE;
    drv->capa.auth = WPA_DRIVER_AUTH_OPEN |
        WPA_DRIVER_AUTH_SHARED |
        WPA_DRIVER_AUTH_LEAP;
    drv->capa.max_scan_ssids = 1;

    wpa_printf(MSG_DEBUG, "  capabilities: key_mgmt 0x%x enc 0x%x "
           "flags 0x%x",
           drv->capa.key_mgmt, drv->capa.enc, drv->capa.flags);
    } else {
    wpa_printf(MSG_DEBUG, "SIOCGIWRANGE: too old (short) data - "
           "assuming WPA is not supported");
    }

    os_free(range);
    return 0;
}


static int ar6003_driver_set_psk(struct ar6003_driver_data *drv,
               const u8 *psk)
{
    struct iw_encode_ext *ext;
    struct iwreq iwr;
    int ret;

    wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);

    if (!(drv->capa.flags & WPA_DRIVER_FLAGS_4WAY_HANDSHAKE))
    return 0;

    if (!psk)
    return 0;

    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);

    ext = os_zalloc(sizeof(*ext) + PMK_LEN);
    if (ext == NULL)
    return -1;

    iwr.u.encoding.pointer = (caddr_t) ext;
    iwr.u.encoding.length = sizeof(*ext) + PMK_LEN;
    ext->key_len = PMK_LEN;
    os_memcpy(&ext->key, psk, ext->key_len);
    ext->alg = IW_ENCODE_ALG_PMK;

    ret = ioctl(drv->ioctl_sock, SIOCSIWENCODEEXT, &iwr);
    if (ret < 0)
    perror("ioctl[SIOCSIWENCODEEXT] PMK");
    os_free(ext);

    return ret;
}


static int ar6003_driver_set_key_ext(void *priv, enum wpa_alg alg,
                   const u8 *addr, int key_idx,
                   int set_tx, const u8 *seq,
                   size_t seq_len,
                   const u8 *key, size_t key_len)
{
    struct ar6003_driver_data *drv = priv;
    struct iwreq iwr;
    int ret = 0;
    struct iw_encode_ext *ext;

    if (seq_len > IW_ENCODE_SEQ_MAX_SIZE) {
    wpa_printf(MSG_DEBUG, "%s: Invalid seq_len %lu",
           __FUNCTION__, (unsigned long) seq_len);
    return -1;
    }

    ext = os_zalloc(sizeof(*ext) + key_len);
    if (ext == NULL)
    return -1;
    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.encoding.flags = key_idx + 1;
    iwr.u.encoding.flags |= IW_ENCODE_TEMP;
    if (alg == WPA_ALG_NONE)
    iwr.u.encoding.flags |= IW_ENCODE_DISABLED;
    iwr.u.encoding.pointer = (caddr_t) ext;
    iwr.u.encoding.length = sizeof(*ext) + key_len;

    if (addr == NULL ||
    os_memcmp(addr, "\xff\xff\xff\xff\xff\xff", ETH_ALEN) == 0)
    ext->ext_flags |= IW_ENCODE_EXT_GROUP_KEY;
    if (set_tx)
    ext->ext_flags |= IW_ENCODE_EXT_SET_TX_KEY;

    ext->addr.sa_family = ARPHRD_ETHER;
    if (addr)
    os_memcpy(ext->addr.sa_data, addr, ETH_ALEN);
    else
    os_memset(ext->addr.sa_data, 0xff, ETH_ALEN);
    if (key && key_len) {
    os_memcpy(ext + 1, key, key_len);
    ext->key_len = key_len;
    }
    switch (alg) {
    case WPA_ALG_NONE:
    ext->alg = IW_ENCODE_ALG_NONE;
    break;
    case WPA_ALG_WEP:
    ext->alg = IW_ENCODE_ALG_WEP;
    break;
    case WPA_ALG_TKIP:
    ext->alg = IW_ENCODE_ALG_TKIP;
    break;
    case WPA_ALG_CCMP:
    ext->alg = IW_ENCODE_ALG_CCMP;
    break;
    case WPA_ALG_PMK:
    ext->alg = IW_ENCODE_ALG_PMK;
    break;
#ifdef CONFIG_IEEE80211W
    case WPA_ALG_IGTK:
    ext->alg = IW_ENCODE_ALG_AES_CMAC;
    break;
#endif /* CONFIG_IEEE80211W */
    default:
    wpa_printf(MSG_DEBUG, "%s: Unknown algorithm %d",
           __FUNCTION__, alg);
    os_free(ext);
    return -1;
    }

    if (seq && seq_len) {
    ext->ext_flags |= IW_ENCODE_EXT_RX_SEQ_VALID;
    os_memcpy(ext->rx_seq, seq, seq_len);
    }

    if (ioctl(drv->ioctl_sock, SIOCSIWENCODEEXT, &iwr) < 0) {
    ret = errno == EOPNOTSUPP ? -2 : -1;
    if (errno == ENODEV) {
        /*
         * ndiswrapper seems to be returning incorrect error
         * code.. */
        ret = -2;
    }

    perror("ioctl[SIOCSIWENCODEEXT]");
    }

    os_free(ext);
    return ret;
}


/**
 * ar6003_driver_set_key - Configure encryption key
 * @priv: Pointer to private data from ar6003_driver_init()
 * @priv: Private driver interface data
 * @alg: Encryption algorithm (%WPA_ALG_NONE, %WPA_ALG_WEP,
 *    %WPA_ALG_TKIP, %WPA_ALG_CCMP); %WPA_ALG_NONE clears the key.
 * @addr: Address of the peer STA or ff:ff:ff:ff:ff:ff for
 *    broadcast/default keys
 * @key_idx: key index (0..3), usually 0 for unicast keys
 * @set_tx: Configure this key as the default Tx key (only used when
 *    driver does not support separate unicast/individual key
 * @seq: Sequence number/packet number, seq_len octets, the next
 *    packet number to be used for in replay protection; configured
 *    for Rx keys (in most cases, this is only used with broadcast
 *    keys and set to zero for unicast keys)
 * @seq_len: Length of the seq, depends on the algorithm:
 *    TKIP: 6 octets, CCMP: 6 octets
 * @key: Key buffer; TKIP: 16-byte temporal key, 8-byte Tx Mic key,
 *    8-byte Rx Mic Key
 * @key_len: Length of the key buffer in octets (WEP: 5 or 13,
 *    TKIP: 32, CCMP: 16)
 * Returns: 0 on success, -1 on failure
 *
 * This function uses SIOCSIWENCODEEXT by default, but tries to use
 * SIOCSIWENCODE if the extended ioctl fails when configuring a WEP key.
 */
int ar6003_driver_set_key(const char *ifname, void *priv, enum wpa_alg alg,
            const u8 *addr, int key_idx,
            int set_tx, const u8 *seq, size_t seq_len,
            const u8 *key, size_t key_len)
{
    struct ar6003_driver_data *drv = priv;
    struct iwreq iwr;
    int ret = 0;

    wpa_printf(MSG_DEBUG, "%s: alg=%d key_idx=%d set_tx=%d seq_len=%lu "
       "key_len=%lu",
       __FUNCTION__, alg, key_idx, set_tx,
       (unsigned long) seq_len, (unsigned long) key_len);

    ret = ar6003_driver_set_key_ext(drv, alg, addr, key_idx, set_tx,
                  seq, seq_len, key, key_len);
    if (ret == 0)
    return 0;

    if (ret == -2 &&
    (alg == WPA_ALG_NONE || alg == WPA_ALG_WEP)) {
    wpa_printf(MSG_DEBUG, "Driver did not support "
           "SIOCSIWENCODEEXT, trying SIOCSIWENCODE");
    ret = 0;
    } else {
    wpa_printf(MSG_DEBUG, "Driver did not support "
           "SIOCSIWENCODEEXT");
    return ret;
    }

    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.encoding.flags = key_idx + 1;
    iwr.u.encoding.flags |= IW_ENCODE_TEMP;
    if (alg == WPA_ALG_NONE)
    iwr.u.encoding.flags |= IW_ENCODE_DISABLED;
    iwr.u.encoding.pointer = (caddr_t) key;
    iwr.u.encoding.length = key_len;

    if (ioctl(drv->ioctl_sock, SIOCSIWENCODE, &iwr) < 0) {
    perror("ioctl[SIOCSIWENCODE]");
    ret = -1;
    }

    if (set_tx && alg != WPA_ALG_NONE) {
    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.encoding.flags = key_idx + 1;
    iwr.u.encoding.flags |= IW_ENCODE_TEMP;
    iwr.u.encoding.pointer = (caddr_t) NULL;
    iwr.u.encoding.length = 0;
    if (ioctl(drv->ioctl_sock, SIOCSIWENCODE, &iwr) < 0) {
        perror("ioctl[SIOCSIWENCODE] (set_tx)");
        ret = -1;
    }
    }

    return ret;
}


static int ar6003_driver_set_countermeasures(void *priv,
                       int enabled)
{
    struct ar6003_driver_data *drv = priv;
    wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);
    return ar6003_driver_set_auth_param(drv,
                      IW_AUTH_TKIP_COUNTERMEASURES,
                      enabled);
}


static int ar6003_driver_set_drop_unencrypted(void *priv,
                    int enabled)
{
    struct ar6003_driver_data *drv = priv;
    wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);
    drv->use_crypt = enabled;
    return ar6003_driver_set_auth_param(drv, IW_AUTH_DROP_UNENCRYPTED,
                      enabled);
}


static int ar6003_driver_mlme(struct ar6003_driver_data *drv,
            const u8 *addr, int cmd, int reason_code)
{
    struct iwreq iwr;
    struct iw_mlme mlme;
    int ret = 0;

    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    os_memset(&mlme, 0, sizeof(mlme));
    mlme.cmd = cmd;
    mlme.reason_code = reason_code;
    mlme.addr.sa_family = ARPHRD_ETHER;
    os_memcpy(mlme.addr.sa_data, addr, ETH_ALEN);
    iwr.u.data.pointer = (caddr_t) &mlme;
    iwr.u.data.length = sizeof(mlme);

    if (ioctl(drv->ioctl_sock, SIOCSIWMLME, &iwr) < 0) {
    perror("ioctl[SIOCSIWMLME]");
    ret = -1;
    }

    return ret;
}


static void ar6003_driver_disconnect(struct ar6003_driver_data *drv)
{
    struct iwreq iwr;
    const u8 null_bssid[ETH_ALEN] = { 0, 0, 0, 0, 0, 0 };
    //u8 ssid[32];
    //int i;

    /*
     * Only force-disconnect when the card is in infrastructure mode,
     * otherwise the driver might interpret the cleared BSSID and random
     * SSID as an attempt to create a new ad-hoc network.
     */
    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    if (ioctl(drv->ioctl_sock, SIOCGIWMODE, &iwr) < 0) {
        perror("ioctl[SIOCGIWMODE]");
        iwr.u.mode = IW_MODE_INFRA;
    }

    if (iwr.u.mode == IW_MODE_INFRA) {
    if (drv->cfg80211) {
        /*
         * cfg80211 supports SIOCSIWMLME commands, so there is
         * no need for the random SSID hack, but clear the
         * BSSID and SSID.
         */
        if (ar6003_driver_set_bssid(drv, null_bssid) < 0 ||
            ar6003_driver_set_ssid(drv, (u8 *) "", 0) < 0) {
            wpa_printf(MSG_DEBUG, "Failed to clear "
                   "to disconnect");
        }
        return;
    }
    /*
     * Clear the BSSID selection and set a random SSID to make sure
     * the driver will not be trying to associate with something
     * even if it does not understand SIOCSIWMLME commands (or
     * tries to associate automatically after deauth/disassoc).
     */
    /*for (i = 0; i < 32; i++)
        ssid[i] = rand() & 0xFF;
    
    if (ar6003_driver_set_bssid(drv, null_bssid) < 0 ||
        ar6003_driver_set_ssid(drv, ssid, 32) < 0) {
        wpa_printf(MSG_DEBUG, "Failed to set bogus "
               "BSSID/SSID to disconnect");
    } */
    }
}


static int ar6003_driver_deauthenticate(void *priv, const u8 *addr,
                  int reason_code)
{
    struct ar6003_driver_data *drv = priv;
    int ret;
    wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);
    ret = ar6003_driver_mlme(drv, addr, IW_MLME_DEAUTH, reason_code);
    ar6003_driver_disconnect(drv);
    return ret;
}


static int ar6003_driver_disassociate(void *priv, const u8 *addr,
                int reason_code)
{
    struct ar6003_driver_data *drv = priv;
    int ret;
    wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);
    ret = ar6003_driver_mlme(drv, addr, IW_MLME_DISASSOC, reason_code);
    ar6003_driver_disconnect(drv);
    return ret;
}


static int ar6003_driver_set_gen_ie(void *priv, const u8 *ie,
                  size_t ie_len)
{
    struct ar6003_driver_data *drv = priv;
    struct iwreq iwr;
    int ret = 0;

    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.data.pointer = (caddr_t) ie;
    iwr.u.data.length = ie_len;

    if (ioctl(drv->ioctl_sock, SIOCSIWGENIE, &iwr) < 0) {
    perror("ioctl[SIOCSIWGENIE]");
    ret = -1;
    }

    return ret;
}


int ar6003_driver_cipher2wext(int cipher)
{
    switch (cipher) {
    case CIPHER_NONE:
    return IW_AUTH_CIPHER_NONE;
    case CIPHER_WEP40:
    return IW_AUTH_CIPHER_WEP40;
    case CIPHER_TKIP:
    return IW_AUTH_CIPHER_TKIP;
    case CIPHER_CCMP:
    return IW_AUTH_CIPHER_CCMP;
    case CIPHER_WEP104:
    return IW_AUTH_CIPHER_WEP104;
    default:
    return 0;
    }
}


int ar6003_driver_keymgmt2wext(int keymgmt)
{
    switch (keymgmt) {
    case KEY_MGMT_802_1X:
    case KEY_MGMT_802_1X_NO_WPA:
    return IW_AUTH_KEY_MGMT_802_1X;
    case KEY_MGMT_PSK:
    return IW_AUTH_KEY_MGMT_PSK;
    default:
    return 0;
    }
}


static int
ar6003_driver_auth_alg_fallback(struct ar6003_driver_data *drv,
              struct wpa_driver_associate_params *params)
{
    struct iwreq iwr;
    int ret = 0;

    wpa_printf(MSG_DEBUG, "Driver did not support "
       "SIOCSIWAUTH for AUTH_ALG, trying SIOCSIWENCODE");

    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    /* Just changing mode, not actual keys */
    iwr.u.encoding.flags = 0;
    iwr.u.encoding.pointer = (caddr_t) NULL;
    iwr.u.encoding.length = 0;

    /*
     * Note: IW_ENCODE_{OPEN,RESTRICTED} can be interpreted to mean two
     * different things. Here they are used to indicate Open System vs.
     * Shared Key authentication algorithm. However, some drivers may use
     * them to select between open/restricted WEP encrypted (open = allow
     * both unencrypted and encrypted frames; restricted = only allow
     * encrypted frames).
     */

    if (!drv->use_crypt) {
    iwr.u.encoding.flags |= IW_ENCODE_DISABLED;
    } else {
    if (params->auth_alg & WPA_AUTH_ALG_OPEN)
        iwr.u.encoding.flags |= IW_ENCODE_OPEN;
    if (params->auth_alg & WPA_AUTH_ALG_SHARED)
        iwr.u.encoding.flags |= IW_ENCODE_RESTRICTED;
    }

    if (ioctl(drv->ioctl_sock, SIOCSIWENCODE, &iwr) < 0) {
    perror("ioctl[SIOCSIWENCODE]");
    ret = -1;
    }

    return ret;
}

int ar6003_driver_associate(void *priv,
              struct wpa_driver_associate_params *params)
{
    struct ar6003_driver_data *drv = priv;
    int ret = 0;
    int allow_unencrypted_eapol;
    int value;

    wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);
    
    if (drv->cfg80211) {
    /*
     * Stop cfg80211 from trying to associate before we are done
     * with all parameters.
     */
    ar6003_driver_set_ssid(drv, (u8 *) "", 0);
    }

    if (ar6003_driver_set_drop_unencrypted(drv, params->drop_unencrypted)
    < 0)
    ret = -1;

    if (ar6003_driver_set_auth_alg(drv, params->auth_alg) < 0)
    ret = -1;
    if (ar6003_driver_set_mode(drv, params->mode) < 0)
    ret = -1;

    /*
     * If the driver did not support SIOCSIWAUTH, fallback to
     * SIOCSIWENCODE here.
     */
    if (drv->auth_alg_fallback &&
    ar6003_driver_auth_alg_fallback(drv, params) < 0)
    ret = -1;

    if (!params->bssid &&
    ar6003_driver_set_bssid(drv, NULL) < 0)
    ret = -1;

    /* TODO: should consider getting wpa version and cipher/key_mgmt suites
     * from configuration, not from here, where only the selected suite is
     * available */

    if(params->mode != IEEE80211_MODE_AP) {
    if (ar6003_driver_set_gen_ie(drv, params->wpa_ie, params->wpa_ie_len)
    < 0)
    ret = -1;
    
    if (params->wpa_ie == NULL || params->wpa_ie_len == 0)
    value = IW_AUTH_WPA_VERSION_DISABLED;
    else if (params->wpa_ie[0] == WLAN_EID_RSN)
    value = IW_AUTH_WPA_VERSION_WPA2;
    else
    value = IW_AUTH_WPA_VERSION_WPA;
    if (ar6003_driver_set_auth_param(drv,
                   IW_AUTH_WPA_VERSION, value) < 0)
    ret = -1;

    value = ar6003_driver_keymgmt2wext(params->key_mgmt_suite);
    if (ar6003_driver_set_auth_param(drv,
                   IW_AUTH_KEY_MGMT, value) < 0)
    ret = -1;
    }
    value = ar6003_driver_cipher2wext(params->pairwise_suite);
    if (ar6003_driver_set_auth_param(drv,
                   IW_AUTH_CIPHER_PAIRWISE, value) < 0)
    ret = -1;
    value = ar6003_driver_cipher2wext(params->group_suite);
    if (ar6003_driver_set_auth_param(drv,
                   IW_AUTH_CIPHER_GROUP, value) < 0)
    ret = -1;
    
    value = params->key_mgmt_suite != KEY_MGMT_NONE ||
    params->pairwise_suite != CIPHER_NONE ||
    params->group_suite != CIPHER_NONE ||
    params->wpa_ie_len;
    if (ar6003_driver_set_auth_param(drv,
                   IW_AUTH_PRIVACY_INVOKED, value) < 0)
    ret = -1;

    /* Allow unencrypted EAPOL messages even if pairwise keys are set when
     * not using WPA. IEEE 802.1X specifies that these frames are not
     * encrypted, but WPA encrypts them when pairwise keys are in use. */
    if (params->key_mgmt_suite == KEY_MGMT_802_1X ||
    params->key_mgmt_suite == KEY_MGMT_PSK)
    allow_unencrypted_eapol = 0;
    else
    allow_unencrypted_eapol = 1;

    if (ar6003_driver_set_psk(drv, params->psk) < 0)
    ret = -1;
    if (ar6003_driver_set_auth_param(drv,
                   IW_AUTH_RX_UNENCRYPTED_EAPOL,
                   allow_unencrypted_eapol) < 0)
    ret = -1;
#ifdef CONFIG_IEEE80211W
    switch (params->mgmt_frame_protection) {
    case NO_MGMT_FRAME_PROTECTION:
    value = IW_AUTH_MFP_DISABLED;
    break;
    case MGMT_FRAME_PROTECTION_OPTIONAL:
    value = IW_AUTH_MFP_OPTIONAL;
    break;
    case MGMT_FRAME_PROTECTION_REQUIRED:
    value = IW_AUTH_MFP_REQUIRED;
    break;
    };
    if (ar6003_driver_set_auth_param(drv, IW_AUTH_MFP, value) < 0)
    ret = -1;
#endif /* CONFIG_IEEE80211W */
    if (params->freq && ar6003_driver_set_freq(drv, params->freq) < 0)
    ret = -1;

    if (params->bssid &&
    ar6003_driver_set_bssid(drv, params->bssid) < 0)
    ret = -1;
    
    if (params->ssid &&
    ar6003_driver_set_ssid(drv, params->ssid, params->ssid_len) < 0)
    ret = -1;

    return ret;
}


static int ar6003_driver_set_auth_alg(void *priv, int auth_alg)
{
    struct ar6003_driver_data *drv = priv;
    int algs = 0, res;

    if (auth_alg & WPA_AUTH_ALG_OPEN)
    algs |= IW_AUTH_ALG_OPEN_SYSTEM;
    if (auth_alg & WPA_AUTH_ALG_SHARED)
    algs |= IW_AUTH_ALG_SHARED_KEY;
    if (auth_alg & WPA_AUTH_ALG_LEAP)
    algs |= IW_AUTH_ALG_LEAP;
    if (algs == 0) {
    /* at least one algorithm should be set */
    algs = IW_AUTH_ALG_OPEN_SYSTEM;
    }

    res = ar6003_driver_set_auth_param(drv, IW_AUTH_80211_AUTH_ALG,
                     algs);
    drv->auth_alg_fallback = res == -2;
    return res;
}


/**
 * ar6003_driver_set_mode - Set wireless mode (infra/adhoc), SIOCSIWMODE
 * @priv: Pointer to private data from ar6003_driver_init()
 * @mode: 0 = infra/BSS (associate with an AP), 1 = adhoc/IBSS
 * Returns: 0 on success, -1 on failure
 */
int ar6003_driver_set_mode(void *priv, int mode)
{
    struct ar6003_driver_data *drv = priv;
    struct iwreq iwr;
    int ret = -1;
    unsigned int new_mode;

    switch (mode) {
    case 0:
    new_mode = IW_MODE_INFRA;
    break;
    case 1:
    new_mode = IW_MODE_ADHOC;
    break;
    case 2:
    new_mode = IW_MODE_MASTER;
    break;
    default:
    return -1;
    }
    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.mode = new_mode;
    if (ioctl(drv->ioctl_sock, SIOCSIWMODE, &iwr) == 0) {
    ret = 0;
    goto done;
    }

    if (errno != EBUSY) {
    perror("ioctl[SIOCSIWMODE]");
    goto done;
    }

    /* mac80211 doesn't allow mode changes while the device is up, so if
     * the device isn't in the mode we're about to change to, take device
     * down, try to set the mode again, and bring it back up.
     */
    if (ioctl(drv->ioctl_sock, SIOCGIWMODE, &iwr) < 0) {
    perror("ioctl[SIOCGIWMODE]");
    goto done;
    }

    if (iwr.u.mode == new_mode) {
    ret = 0;
    goto done;
    }

    if (linux_set_iface_flags(drv->ioctl_sock, drv->ifname, 0) == 0) {
    /* Try to set the mode again while the interface is down */
    iwr.u.mode = new_mode;
    if (ioctl(drv->ioctl_sock, SIOCSIWMODE, &iwr) < 0)
        perror("ioctl[SIOCSIWMODE]");
    else
        ret = 0;

    (void) linux_set_iface_flags(drv->ioctl_sock, drv->ifname, 1);
    }

done:
    return ret;
}


static int ar6003_driver_pmksa(struct ar6003_driver_data *drv,
             u32 cmd, const u8 *bssid, const u8 *pmkid)
{
    struct iwreq iwr;
    struct iw_pmksa pmksa;
    int ret = 0;

    os_memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    os_memset(&pmksa, 0, sizeof(pmksa));
    pmksa.cmd = cmd;
    pmksa.bssid.sa_family = ARPHRD_ETHER;
    if (bssid)
    os_memcpy(pmksa.bssid.sa_data, bssid, ETH_ALEN);
    if (pmkid)
    os_memcpy(pmksa.pmkid, pmkid, IW_PMKID_LEN);
    iwr.u.data.pointer = (caddr_t) &pmksa;
    iwr.u.data.length = sizeof(pmksa);

    if (ioctl(drv->ioctl_sock, SIOCSIWPMKSA, &iwr) < 0) {
    if (errno != EOPNOTSUPP)
        perror("ioctl[SIOCSIWPMKSA]");
    ret = -1;
    }

    return ret;
}


static int ar6003_driver_add_pmkid(void *priv, const u8 *bssid,
                 const u8 *pmkid)
{
    struct ar6003_driver_data *drv = priv;
    return ar6003_driver_pmksa(drv, IW_PMKSA_ADD, bssid, pmkid);
}


static int ar6003_driver_remove_pmkid(void *priv, const u8 *bssid,
                 const u8 *pmkid)
{
    struct ar6003_driver_data *drv = priv;
    return ar6003_driver_pmksa(drv, IW_PMKSA_REMOVE, bssid, pmkid);
}


static int ar6003_driver_flush_pmkid(void *priv)
{
    struct ar6003_driver_data *drv = priv;
    return ar6003_driver_pmksa(drv, IW_PMKSA_FLUSH, NULL, NULL);
}


int ar6003_driver_get_capa(void *priv, struct wpa_driver_capa *capa)
{
    struct ar6003_driver_data *drv = priv;
    if (!drv->has_capability)
    return -1;
    os_memcpy(capa, &drv->capa, sizeof(*capa));
    return 0;
}


int ar6003_driver_alternative_ifindex(struct ar6003_driver_data *drv,
                const char *ifname)
{
    if (ifname == NULL) {
    drv->ifindex2 = -1;
    return 0;
    }

    drv->ifindex2 = if_nametoindex(ifname);
    if (drv->ifindex2 <= 0)
    return -1;

    wpa_printf(MSG_DEBUG, "Added alternative ifindex %d (%s) for "
       "wireless events", drv->ifindex2, ifname);

    return 0;
}


int ar6003_driver_set_operstate(void *priv, int state)
{
    struct ar6003_driver_data *drv = priv;

    wpa_printf(MSG_DEBUG, "%s: operstate %d->%d (%s)",
       __func__, drv->operstate, state, state ? "UP" : "DORMANT");
    drv->operstate = state;
    return netlink_send_oper_ifla(drv->netlink, drv->ifindex, -1,
                  state ? IF_OPER_UP : IF_OPER_DORMANT);
}


int ar6003_driver_get_version(struct ar6003_driver_data *drv)
{
    return drv->we_version_compiled;
}
#ifdef CONFIG_P2P
static int ar6003_p2p_stop_device_discover(struct ar6003_driver_data *drv)
{
    struct ifreq ifr;
    char buf[8];

    os_memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);
    ((int *)buf)[0] = AR6000_XIOCTL_WMI_P2P_STOP_FIND;

    ifr.ifr_data = buf;
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
        perror("ioctl[ar6003_EXTENDED,P2P_STOP_FIND]");
        return -1;
    }
    return 0;
}

static int ar6003_p2p_device_discover(struct ar6003_driver_data *drv,
                                   unsigned int timeout,int type)
{
    struct ifreq ifr;
    char buf[16];
    WMI_P2P_FIND_CMD *params=NULL;

    os_memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);
    ((int *)buf)[0] = AR6000_XIOCTL_WMI_P2P_DISCOVER;

printf("cmd: %d\n",((int *)buf)[0]);

    params = (WMI_P2P_FIND_CMD *)&buf[4]; 
    params->timeout = timeout;
    params->type = type;
    ifr.ifr_data = buf;
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
            perror("ioctl[ar6003_EXTENDED,P2P_DEVICE_DISCOVER]");
            return -1;
    }
    return 0;
}       

static int ar6003_driver_p2p_find(void *priv, unsigned int timeout, int type)
{
    struct ar6003_driver_data *drv = priv;
    wpa_printf(MSG_DEBUG, "%s(timeout=%u)", __func__, timeout);
printf(__func__);
    if (timeout == 0)
          timeout = 3600;
    return ar6003_p2p_device_discover(drv, timeout, type);
}

static int ar6003_driver_p2p_stop_find(void *priv)
{
    struct ar6003_driver_data *drv = priv;
    wpa_printf(MSG_DEBUG, "%s", __func__);
    return ar6003_p2p_stop_device_discover(drv);
}

static int ar6003_driver_p2p_listen(void *priv, unsigned int timeout)
{
    struct ar6003_driver_data *drv = priv;
    struct ifreq ifr;
    char buf[16];
    wpa_printf(MSG_DEBUG, "%s", __func__);
    os_memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);
    ((int *)buf)[0] = AR6000_XIOCTL_WMI_P2P_LISTEN;
    ((unsigned int *)buf)[1]= timeout;
    ifr.ifr_data = buf;
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
            perror("ioctl[AR6000_EXTENDED,P2P_LISTEN]");
            return -1;
    }
    return 0;
}

static int ar6003_driver_p2p_connect(void *priv, const u8 *peer_addr,
                                    int wps_method, int go_intent,
                                   const u8 *own_interface_addr,
                                   unsigned int force_freq, int persistent_group)
{
    struct ar6003_driver_data *drv = priv;
    char buf[256];
    u16 listen_chan = 0;
    struct ifreq ifr;
    WMI_P2P_GO_NEG_START_CMD *params;

    wpa_printf(MSG_DEBUG, "%s", __func__);

    os_memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);

    os_memset(buf, 0, sizeof(buf));

    ((int *)buf)[0] = AR6000_XIOCTL_WMI_P2P_FINDNODE;
    os_memcpy(&(((int *)buf)[1]), peer_addr, ETH_ALEN);
    ifr.ifr_data = buf; 
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
            perror("ioctl[ar6003_EXTENDED,P2P_FINDNODE]");
            return -1;
    }
    listen_chan = (*((u16 *)(ifr.ifr_data))); 

    os_memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);

    os_memset(buf, 0, sizeof(buf));

    ((int *)buf)[0] = AR6000_XIOCTL_WMI_P2P_GO_NEG;
    params = (WMI_P2P_GO_NEG_START_CMD *)&buf[4]; 
    os_memcpy(params->peer_addr, peer_addr, ETH_ALEN);
    os_memcpy(params->own_interface_addr, own_interface_addr, ETH_ALEN);
    params->listen_freq = listen_chan; 
    params->wps_method = wps_method;
    params->go_intent = go_intent;
    params->force_freq = force_freq;

    ifr.ifr_data = buf;
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
            perror("ioctl[AR6000_IOCTL_EXTENDED,P2P_GO_NEG]");
            return -1;
    }

    return 0;
}

static int ar6003_driver_p2p_auth_go_neg(void *priv, const u8 *peer_addr,
                           int wps_method, int go_intent,
                           const u8 *own_interface_addr,
                           unsigned int force_freq, int persistent_group)
{
    struct ar6003_driver_data *drv = priv;
    char buf[256];
    struct ifreq ifr;
    WMI_P2P_GO_NEG_START_CMD *params;

    wpa_printf(MSG_DEBUG, "%s", __func__);

    os_memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);

    os_memset(buf, 0, sizeof(buf));

    ((int *)buf)[0] = AR6000_XIOCTL_WMI_P2P_AUTH_GO_NEG;
    params = (WMI_P2P_GO_NEG_START_CMD *)&buf[4]; 
    os_memcpy(params->peer_addr, peer_addr, ETH_ALEN);
    os_memcpy(params->own_interface_addr, own_interface_addr, ETH_ALEN);
    params->wps_method = wps_method;
    params->go_intent = go_intent;

    ifr.ifr_data = buf;
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
            perror("ioctl[AR6000_IOCTL_EXTENDED,P2P_AUTH_GO_NEG]");
            return -1;
    }

    return 0;
}

static int ar6003_driver_p2p_prov_disc(void *priv, const u8 *peer_addr,
                u16 config_methods)
{
    struct ar6003_driver_data *drv = priv;
    char buf[256];
    struct ifreq ifr;
    char *pos;

    os_memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);

    os_memset(buf, 0, sizeof(buf));

    ((int *)buf)[0] = AR6000_XIOCTL_WMI_P2P_PROV_DISC;
    pos = (char *)((int *)buf + 1);

    os_memcpy(&(((int *)buf)[1]), peer_addr, ETH_ALEN);

    *((u16 *)(pos+ETH_ALEN)) = config_methods;
    
    ifr.ifr_data = buf; 
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
            perror("ioctl[ar6003_EXTENDED,P2P_PROV_DISC_REQ]");
            return -1;
    }

    wpa_printf(MSG_DEBUG, "P2P_PROV_DISC_REQ \
         %s(peer_addr=" MACSTR ", config_method: %x)",
             __func__, MAC2STR(peer_addr), config_methods);
    return 0;
}

static int ar6003_driver_p2p_reject(void *priv, const u8 *peer_addr)
{
    struct ar6003_driver_data *drv = priv;
    char buf[256];
    struct ifreq ifr;

    os_memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);

    os_memset(buf, 0, sizeof(buf));

    ((int *)buf)[0] = AR6000_XIOCTL_WMI_P2P_REJECT;
    os_memcpy(&(((int *)buf)[1]), peer_addr, ETH_ALEN);
    
    ifr.ifr_data = buf; 
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
            perror("ioctl[ar6003_EXTENDED,P2P_REJECT]");
            return -1;
    }

    wpa_printf(MSG_DEBUG, "P2P_REJECT %s(peer_addr=" MACSTR ")",
               __func__, MAC2STR(peer_addr));
    return 0;
}

static int ar6003_driver_p2p_peer(void *priv, char *cmd, char *reply_buf, size_t buflen)
{
    struct ar6003_driver_data *drv = priv;
    char buf[128];
    struct ifreq ifr;
	u8 addr[ETH_ALEN], *addr_ptr;
	int next;

    wpa_printf(MSG_DEBUG, "%s", __func__);

    if (os_strcmp(cmd, "FIRST") == 0) {
		addr_ptr = NULL;
		next = 0;
	} else if (os_strncmp(cmd, "NEXT-", 5) == 0) {
		if (hwaddr_aton(cmd + 5, addr) < 0)
			return -1;
		addr_ptr = addr;
		next = 1;
	} else {
		if (hwaddr_aton(cmd, addr) < 0)
			return -1;
		addr_ptr = addr;
		next = 0;
	}

    os_memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);

    os_memset(buf, 0, sizeof(buf));
    ((int *)buf)[0] = AR6000_XIOCTL_WMI_P2P_PEER;
    os_memcpy(&(((int *)buf)[1]), addr, ETH_ALEN);
    buf[10] = next;

    ifr.ifr_data = buf; 
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
        perror("ioctl[ar6003_EXTENDED,P2P_PEER]");
        return -1;
    }

    if (is_zero_ether_addr((u8 *)(ifr.ifr_data))) {
        return -1;
    }
    /* Copy the addr to the reply buffer */
    os_snprintf(reply_buf, buflen, MACSTR "\n", MAC2STR(addr));
printf("%s", reply_buf);
    wpa_printf(MSG_DEBUG, "P2P_PEER %s", __func__);
    return 0;
}

static int ar6003_driver_p2p_set_config(void *priv, char *cmd)
{
    char *param;
    struct ar6003_driver_data *drv = priv;
    char buf[128];
    struct ifreq ifr;
    WMI_P2P_SET_CMD *config;

    wpa_printf(MSG_DEBUG, "%s", __func__);

    os_memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);

    os_memset(buf, 0, sizeof(buf));
    ((int *)buf)[0] = AR6000_XIOCTL_WMI_P2P_SET;

    config = (WMI_P2P_SET_CMD *)&buf[4]; 

    param = os_strchr(cmd, ' ');
    if (param == NULL)
    	return -1;
    *param++ = '\0';

    if (os_strcmp(cmd, "listen_channel") == 0) {
        config->config_id = WMI_P2P_CONFID_LISTEN_CHANNEL;
        config->val.listen_ch.listen_channel = atoi(param);
    }
    
    ifr.ifr_data = buf; 
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
            perror("ioctl[ar6003_EXTENDED,P2P_SET]");
            return -1;
    }

    wpa_printf(MSG_DEBUG, "P2P_SET %s", __func__);
    return 0;
}

static int ar6003_driver_wps_success_cb(void *priv, const u8 *peer_addr)
{
    struct ar6003_driver_data *drv = priv;
    char buf[256];
    struct ifreq ifr;

    os_memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);

    os_memset(buf, 0, sizeof(buf));

    ((int *)buf)[0] = AR6000_XIOCTL_WMI_P2P_GRP_FORMATION_DONE;
    os_memcpy(&(((int *)buf)[1]), peer_addr, ETH_ALEN);
    (*(((unsigned char *)buf)+4+ETH_ALEN))= 1; /* Success Status code */
    
    ifr.ifr_data = buf; 
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
            perror("ioctl[ar6003_EXTENDED,P2P_GRP_FORMATION_DONE]");
            return -1;
    }

    wpa_printf(MSG_DEBUG, "WPS_SUCCESS %s(peer_addr=" MACSTR ")",
               __func__, MAC2STR(peer_addr));
    return 0;
}


static int ar6003_driver_p2p_group_formation_failed(void *priv)
{
    struct ar6003_driver_data *drv = priv;
    char buf[256];
    struct ifreq ifr;

    os_memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);

    os_memset(buf, 0, sizeof(buf));

    ((int *)buf)[0] = AR6000_XIOCTL_WMI_P2P_GRP_FORMATION_DONE;
    ((unsigned char *)buf)[1]= 0; /* Failure Status code */
    
    ifr.ifr_data = buf; 
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
            perror("ioctl[ar6003_EXTENDED,P2P_GRP_FORMATION_DONE]");
            return -1;
    }
    wpa_printf(MSG_DEBUG, "P2P_GROUP_FORMATION_FAILED");
    return 0;
}


static int ar6003_driver_wps_set_params(void *priv,
                                      const struct p2p_params *params)
{
    struct ar6003_driver_data *drv = priv;
    WMI_WPS_SET_CONFIG_CMD *config;
    char buf[256];
    struct ifreq ifr;

    wpa_printf(MSG_DEBUG, "%s", __func__);

    os_memset(&ifr, 0, sizeof(ifr));
    os_memset(&buf, 0, 100);
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);

    ((int *)buf)[0] = AR6000_XIOCTL_WMI_WPS_CONFIG;
    config = (WMI_WPS_SET_CONFIG_CMD *)&buf[4]; 

     config->pri_dev_type.categ = params->primary_dev_type.categ;
     config->pri_dev_type.sub_categ = params->primary_dev_type.sub_categ;
     os_memcpy(config->uuid, params->uuid, 16);
     os_memcpy(config->device_name, params->device_name, os_strlen(params->device_name)+1);
     config->dev_name_len = os_strlen(params->device_name);
     ifr.ifr_data = buf;
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
            perror("ioctl[AR6000_IOCTL_EXTENDED,WPS_CONFIG]");
            return -1;
    }
    return 0;
}

static int ar6003_driver_p2p_set_params(void *priv,
                                      const struct p2p_params *params)
{
    struct ar6003_driver_data *drv = priv;
    WMI_P2P_SET_CONFIG_CMD *config;
    char buf[256];
    struct ifreq ifr;
    
    wpa_printf(MSG_DEBUG, "%s", __func__);
    os_memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);

    ((int *)buf)[0] = AR6000_XIOCTL_WMI_P2P_CONFIG;
    config = (WMI_P2P_SET_CONFIG_CMD *)&buf[4]; 
    os_memcpy(config->country, params->country, 3);
    config->reg_class = params->reg_class;
    config->op_reg_class = params->op_reg_class;
    config->op_channel = params->op_channel;
    config->listen_channel = params->listen_channel;
    config->go_intent = params->go_intent;
    ifr.ifr_data = buf;
   
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
            perror("ioctl[AR6000_IOCTL_EXTENDED,P2P_CONFIG]");
            return -1;
    }

    ar6003_driver_wps_set_params(priv, params);        
    return 0;
}

static int ar6003_driver_p2p_group_init(void *priv, int persistent_group, int group_formation)
{
    WMI_P2P_GRP_INIT_CMD *cmd;
    struct ar6003_driver_data *drv = priv;
    char buf[256];
    struct ifreq ifr;
    
    wpa_printf(MSG_DEBUG, "%s", __func__);
    os_memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);

    ((int *)buf)[0] = AR6000_XIOCTL_WMI_P2P_GRP_INIT;
    cmd = (WMI_P2P_GRP_INIT_CMD *)&buf[4]; 
    cmd->persistent_group = persistent_group;
    cmd->group_formation = group_formation;
    ifr.ifr_data = buf;
   
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
        perror("ioctl[AR6000_IOCTL_EXTENDED,P2P_GRP_INIT]");
        return -1;
    }

    return 0;
}

static int ar6003_driver_p2p_invite(void *priv, const u8 *peer, int role,
			  const u8 *bssid, const u8 *ssid, size_t ssid_len,
			  const u8 *go_dev_addr, int persistent_group)
{
    WMI_P2P_INVITE_CMD *cmd;
    struct ar6003_driver_data *drv = priv;
    char buf[256];
    struct ifreq ifr;
    u16 listen_chan = 0;

    wpa_printf(MSG_DEBUG, "%s", __func__);

    os_memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);
    os_memset(buf, 0, sizeof(buf));

    ((int *)buf)[0] = AR6000_XIOCTL_WMI_P2P_FINDNODE;
    os_memcpy(&(((int *)buf)[1]), peer, ETH_ALEN);
    ifr.ifr_data = buf; 

    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
        perror("ioctl[ar6003_EXTENDED,P2P_FINDNODE]");
        return -1;
    }
    listen_chan = (*((u16 *)(ifr.ifr_data))); 

    /* Send the INVITE cmd to the driver
     */
    os_memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);
    os_memset(buf, 0, sizeof(buf));

    ((int *)buf)[0] = AR6000_XIOCTL_WMI_P2P_INVITE;
    cmd = (WMI_P2P_INVITE_CMD *)&buf[4]; 

    //cmd->role = role; // The firmware can determine this for an active grp
    cmd->listen_freq = listen_chan;

    if (peer) {
    os_memcpy(cmd->peer_addr, peer, ETH_ALEN);
    }

    /* The firmware can determine these for an active grp.
     */
    /*if (ssid_len) {
    os_memcpy(cmd->ssid.ssid, ssid, ssid_len);
    cmd->ssid.ssid_len = ssid_len;
    }

    if (bssid) {
    os_memcpy(cmd->bssid, bssid, ETH_ALEN);
    } */

    if (go_dev_addr) {
    os_memcpy(cmd->go_dev_addr, go_dev_addr, ETH_ALEN);
    }

    cmd->is_persistent = persistent_group;

    ifr.ifr_data = buf;
   
    if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
        perror("ioctl[AR6000_IOCTL_EXTENDED,P2P_INVITE]");
        return -1;
    }

    return 0;
}

#endif

/*
 * Configure WPA parameters.
 */
static int
ar6003_configure_wpa(struct ar6003_driver_data *drv,
                 struct wpa_bss_params *conf)
{
    int v;

    switch (conf->wpa_group) {
    case WPA_CIPHER_CCMP:
    v = IEEE80211_CIPHER_AES_CCM;
    break;
    case WPA_CIPHER_TKIP:
    v = IEEE80211_CIPHER_TKIP;
    break;
    case WPA_CIPHER_WEP104:
    v = IEEE80211_CIPHER_WEP;
    break;
    case WPA_CIPHER_WEP40:
    v = IEEE80211_CIPHER_WEP;
    break;
    case WPA_CIPHER_NONE:
    v = IEEE80211_CIPHER_NONE;
    break;
    default:
    wpa_printf(MSG_ERROR, "Unknown group key cipher %u",
        conf->wpa_group);
    return -1;
    }
    wpa_printf(MSG_DEBUG, "%s: group key cipher=%d", __func__, v);
    if (set80211param(drv, IEEE80211_PARAM_MCASTCIPHER, v)) {
    printf("Unable to set group key cipher to %u\n", v);
    return -1;
    }
    if (v == IEEE80211_CIPHER_WEP) {
    /* key length is done only for specific ciphers */
    v = (conf->wpa_group == WPA_CIPHER_WEP104 ? 13 : 5);
    if (set80211param(drv, IEEE80211_PARAM_MCASTKEYLEN, v)) {
        printf("Unable to set group key length to %u\n", v);
        return -1;
    }
    }

    v = 0;
    if (conf->wpa_pairwise & WPA_CIPHER_CCMP)
    v |= 1<<IEEE80211_CIPHER_AES_CCM;
    if (conf->wpa_pairwise & WPA_CIPHER_TKIP)
    v |= 1<<IEEE80211_CIPHER_TKIP;
    if (conf->wpa_pairwise & WPA_CIPHER_NONE)
    v |= 1<<IEEE80211_CIPHER_NONE;
    wpa_printf(MSG_DEBUG,"%s: pairwise key ciphers=0x%x", __func__, v);
    if (set80211param(drv, IEEE80211_PARAM_UCASTCIPHER, v)) {
    printf("Unable to set pairwise key ciphers to 0x%x\n", v);
    return -1;
    }
    wpa_printf(MSG_DEBUG, "%s: enable WPA=0x%x\n", __func__, conf->wpa);
    if (set80211param(drv, IEEE80211_PARAM_WPA, conf->wpa)) {
    printf("Unable to set WPA to %u\n", conf->wpa);
    return -1;
    }
    return 0;
}

static int
set80211param(struct ar6003_driver_data *drv, int op, int arg)
{
    struct iwreq iwr;

    memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.mode = op;
    memcpy(iwr.u.name+sizeof(__u32), &arg, sizeof(arg));

    if (ioctl(drv->ioctl_sock, IEEE80211_IOCTL_SETPARAM, &iwr) < 0) {
    perror("ioctl[IEEE80211_IOCTL_SETPARAM]");
    wpa_printf(MSG_DEBUG, "%s: Failed to set parameter (op %d "
           "arg %d)", __func__, op, arg);
    return -1;
    }
    return 0;
}

static int ar6003_key_mgmt(int key_mgmt, int auth_alg)
{
    switch (key_mgmt) {
    case WPA_KEY_MGMT_IEEE8021X:
    return IEEE80211_AUTH_WPA;
    case WPA_KEY_MGMT_PSK:
    return IEEE80211_AUTH_WPA_PSK;
    default:
    return IEEE80211_AUTH_OPEN;
    }
}

static int
ar6003_set_ieee8021x(void *priv, struct wpa_bss_params *params)
{
    struct ar6003_driver_data *drv = priv;
    int auth;
    
    wpa_printf(MSG_DEBUG, "%s: enabled=%d", __func__, params->enabled);

    if (!params->enabled) {
    /* XXX restore state */
    return set80211param(priv, IEEE80211_PARAM_AUTHMODE,
        IEEE80211_AUTH_AUTO);
    }
    if (!params->wpa && !params->ieee802_1x) {
    hostapd_logger(drv->ctx, NULL, HOSTAPD_MODULE_DRIVER,
        HOSTAPD_LEVEL_WARNING, "No 802.1X or WPA enabled!");
    return -1;
    }
    if (params->wpa && ar6003_configure_wpa(drv, params) != 0) {
    hostapd_logger(drv->ctx, NULL, HOSTAPD_MODULE_DRIVER,
        HOSTAPD_LEVEL_WARNING, "Error configuring WPA state!");
    return -1;
    }
    auth = ar6003_key_mgmt(params->wpa_key_mgmt, AUTH_ALG_OPEN_SYSTEM);
    if (set80211param(priv, IEEE80211_PARAM_AUTHMODE, auth)) {
          hostapd_logger(drv->ctx, NULL, HOSTAPD_MODULE_DRIVER,
           HOSTAPD_LEVEL_WARNING, "Error enabling WPA/802.1X!");
        return -1;
    }  

    return 0;
}


static int
ar6003_set_privacy(void *priv, int enabled)
{
    wpa_printf(MSG_DEBUG, "%s: enabled=%d\n", __func__, enabled);

    return set80211param(priv, IEEE80211_PARAM_PRIVACY, enabled);
}


static int
ar6003_set_wep_key(void *priv, int key_idx, const u8 *key, 
                size_t key_len, int txkey)
{   
    struct ar6003_driver_data *drv = priv;
    struct hostapd_data *hapd = drv->ctx;
    struct hostapd_bss_config *conf = hapd->conf;
    struct iwreq iwr;

    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.data.pointer = (caddr_t) key;
    iwr.u.data.length = key_len;
    iwr.u.data.flags = key_idx+1;

    if(conf->auth_algs & (WPA_AUTH_ALG_OPEN | WPA_AUTH_ALG_SHARED)) {
    if(conf->auth_algs & WPA_AUTH_ALG_OPEN) {
        iwr.u.data.flags |= IW_ENCODE_OPEN;
    } 
    if(conf->auth_algs & WPA_AUTH_ALG_SHARED) {
        iwr.u.data.flags |= IW_ENCODE_RESTRICTED;
    }
    } else {
    wpa_printf(MSG_ERROR, "%s: auth_algs=%d not supported\n", 
        __func__, conf->auth_algs);
    return -1;
    }

    if (ioctl(drv->ioctl_sock, SIOCSIWENCODE, &iwr) < 0) {
    perror("ioctl[SIOCSIWENCODE]");
    return -1;
    }

    if(txkey) {
    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.data.pointer = NULL;
    iwr.u.data.length = 0;
    iwr.u.data.flags = key_idx+1;

    if (ioctl(drv->ioctl_sock, SIOCSIWENCODE, &iwr) < 0) {
        perror("ioctl[SIOCSIWENCODE]");
        return -1;
    }
    }
    return 0;
}

static int
ar6003_del_key(void *priv, const u8 *addr, int key_idx)
{
    
    struct ieee80211req_del_key wk;
    int ret;

    wpa_printf(MSG_DEBUG, "%s: addr=%s key_idx=%d\n",
    __func__, ether_sprintf(addr), key_idx);

    memset(&wk, 0, sizeof(wk));
    if (addr != NULL) {
    memcpy(wk.idk_macaddr, addr, IEEE80211_ADDR_LEN);
    wk.idk_keyix = 0; //(u8) IEEE80211_KEYIX_NONE;
    } else {
    wk.idk_keyix = key_idx;
    }

    ret = set80211priv(priv, IEEE80211_IOCTL_DELKEY, &wk, sizeof(wk));
    if (ret < 0) {
    wpa_printf(MSG_DEBUG, "%s: Failed to delete key (addr %s"
           " key_idx %d)", __func__, ether_sprintf(addr),
           key_idx);
    }

    return ret;
}

static int
ar6003_set_key(const char *ifname, void *priv, enum wpa_alg alg,
    const u8 *addr, int key_idx, int set_tx, const u8 *seq,
    size_t seq_len, const u8 *key, size_t key_len)
{
    struct ar6003_driver_data *drv = priv;
    struct ieee80211req_key wk;
    u_int8_t cipher;
    int ret;

    if (alg == WPA_ALG_NONE)
    return ar6003_del_key(drv, addr, key_idx);

    wpa_printf(MSG_DEBUG, "%s: alg=%d addr=%s key_idx=%d",
       __func__, alg, ether_sprintf(addr), key_idx);

    if(alg == WPA_ALG_WEP) 
    return ar6003_set_wep_key(priv, key_idx, key, key_len, set_tx);
    switch (alg) {
    case WPA_ALG_TKIP:
    cipher = IEEE80211_CIPHER_TKIP;
    break;
    case WPA_ALG_CCMP:
    cipher = IEEE80211_CIPHER_AES_CCM;
    break;
    default:
    printf("%s: unknown/unsupported algorithm %d\n",
        __func__, alg);
    return -1;
    }

    if (key_len > sizeof(wk.ik_keydata)) {
    printf("%s: key length %lu too big\n", __func__,
           (unsigned long) key_len);
    return -3;
    }

    memset(&wk, 0, sizeof(wk));
    wk.ik_type = cipher;
    wk.ik_flags = IEEE80211_KEY_RECV | IEEE80211_KEY_XMIT;
    if ((addr == NULL) || (addr[0] & 0x1)) {
    memset(wk.ik_macaddr, 0xff, IEEE80211_ADDR_LEN);
    wk.ik_keyix = key_idx;
    wk.ik_flags |= IEEE80211_KEY_DEFAULT;
    } else {
    memcpy(wk.ik_macaddr, addr, IEEE80211_ADDR_LEN);
    wk.ik_keyix = 0; //IEEE80211_KEYIX_NONE;
    }
    wk.ik_keylen = key_len;
    memcpy(wk.ik_keydata, key, key_len);

    ret = set80211priv(drv, IEEE80211_IOCTL_SETKEY, &wk, sizeof(wk));
    if (ret < 0) {
    wpa_printf(MSG_DEBUG, "%s: Failed to set key (addr %s"
           " key_idx %d alg %d key_len %lu set_tx %d)",
           __func__, ether_sprintf(wk.ik_macaddr), key_idx,
           alg, (unsigned long) key_len, set_tx);
    }

    return ret;
}


static int
ar6003_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr, 
              int reason_code)
{
    struct ieee80211req_mlme mlme;
    int ret;

    wpa_printf(MSG_DEBUG, "%s: addr=%s reason_code=%d\n",
    __func__, ether_sprintf(addr), reason_code);

    mlme.im_op = IEEE80211_MLME_DEAUTH;
    mlme.im_reason = reason_code;
    memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
    ret = set80211priv(priv, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme));
    if (ret < 0) {
    wpa_printf(MSG_DEBUG, "%s: Failed to deauth STA (addr " MACSTR
           " reason %d)",
           __func__, MAC2STR(addr), reason_code);
    }

    return ret;
}

static int 
ar6003_flush(void *priv)
{
#ifdef AR6000_BSD
    u8 allsta[IEEE80211_ADDR_LEN];
    memset(allsta, 0xff, IEEE80211_ADDR_LEN);
    return ar6003_sta_deauth(priv, NULL, allsta, IEEE80211_REASON_AUTH_LEAVE);
#else /* ar6003_BSD */
    return 0;       /* XXX */
#endif /* ar6003_BSD */
}


static int
ar6003_set_opt_ie(void *priv, const u8 *ie, size_t ie_len)
{
    /*
     * Do nothing; we setup parameters at startup that define the
     * contents of the beacon information element.
     */
    return 0;
}


static int
ar6003_set_sta_authorized(void *priv, const u8 *addr, int authorized)
{
    struct ieee80211req_mlme mlme;
    int ret;

    wpa_printf(MSG_DEBUG, "%s: addr=%s authorized=%d\n",
    __func__, ether_sprintf(addr), authorized);

    if (authorized)
    mlme.im_op = IEEE80211_MLME_AUTHORIZE;
    else
    mlme.im_op = IEEE80211_MLME_UNAUTHORIZE;
    mlme.im_reason = 0;
    memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
    ret = set80211priv(priv, IEEE80211_IOCTL_SETMLME, &mlme,
           sizeof(mlme));
    if (ret < 0) {
    wpa_printf(MSG_DEBUG, "%s: Failed to %sauthorize STA " MACSTR,
           __func__, authorized ? "" : "un", MAC2STR(addr));
    }

    return ret;
}

static int
ar6003_sta_set_flags(void *priv, const u8 *addr,int total_flags, 
                  int flags_or, int flags_and)
{
    /* For now, only support setting Authorized flag */
    if (flags_or & WPA_STA_AUTHORIZED)
    return ar6003_set_sta_authorized(priv, addr, 1);
    if (!(flags_and & WPA_STA_AUTHORIZED))
    return ar6003_set_sta_authorized(priv, addr, 0);
    return 0;
}

static int
ar6003_send_eapol(void *priv, const u8 *addr, const u8 *data, size_t data_len,
       int encrypt, const u8 *own_addr)
{
    struct ar6003_driver_data *drv = priv;
    unsigned char buf[3000];
    unsigned char *bp = buf;
    struct l2_ethhdr *eth;
    size_t len;
    int status;

    /*
     * Prepend the Ethernet header.  If the caller left us
     * space at the front we could just insert it but since
     * we don't know we copy to a local buffer.  Given the frequency
     * and size of frames this probably doesn't matter.
     */
    len = data_len + sizeof(struct l2_ethhdr);
    if (len > sizeof(buf)) {
    bp = malloc(len);
    if (bp == NULL) {
        printf("EAPOL frame discarded, cannot malloc temp "
               "buffer of size %lu!\n", (unsigned long) len);
        return -1;
    }
    }
    eth = (struct l2_ethhdr *) bp;
    memcpy(eth->h_dest, addr, ETH_ALEN);
    memcpy(eth->h_source, own_addr, ETH_ALEN);
    eth->h_proto = htons(ETH_P_EAPOL);
    memcpy(eth+1, data, data_len);

    wpa_hexdump(MSG_MSGDUMP, "TX EAPOL", bp, len);

    status = l2_packet_send(drv->sock_xmit, addr, ETH_P_EAPOL, bp, len);

    if (bp != buf)
    free(bp);
    return status;
}


static int
ar6003_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr,
                int reason_code)
{
    struct ieee80211req_mlme mlme;
    int ret;

    wpa_printf(MSG_DEBUG, "%s: addr=%s reason_code=%d\n",
    __func__, ether_sprintf(addr), reason_code);

    mlme.im_op = IEEE80211_MLME_DISASSOC;
    mlme.im_reason = reason_code;
    memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
    ret = set80211priv(priv, IEEE80211_IOCTL_SETMLME, &mlme, sizeof(mlme));
    if (ret < 0) {
    wpa_printf(MSG_DEBUG, "%s: Failed to disassoc STA (addr "
           MACSTR " reason %d)",
           __func__, MAC2STR(addr), reason_code);
    }

    return ret;
}

static int
ar6003_set_freq(void *priv, struct hostapd_freq_params *freq)
{
    struct ar6003_driver_data *drv = priv;
    struct iwreq iwr;
    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.freq.m = freq->channel;
    
    if (ioctl(drv->ioctl_sock, SIOCSIWFREQ, &iwr) < 0) {
    perror("ioctl[SIOCSIWFREQ]");
    return -1;
    }
    return 0;
}

static int
ar6003_set_ssid(void *priv, const u8 *buf, int len)
{
    struct ar6003_driver_data *drv = priv;
    struct iwreq iwr;
    
    /*if(p2p_state != P2PNEGOCOMPLETE)
    return -1;
    */

    memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.essid.flags = 1; /* SSID active */
    iwr.u.essid.pointer = (caddr_t) buf;
    iwr.u.essid.length = len + 1;

    if (ioctl(drv->ioctl_sock, SIOCSIWESSID, &iwr) < 0) {
    perror("ioctl[SIOCSIWESSID]");
    printf("len=%d\n", len);
    return -1;
    }
    return 0;
}

static int
ar6003_get_ssid(void *priv, u8 *buf, int len)
{
    struct ar6003_driver_data *drv = priv;
    struct iwreq iwr;
    int ret = 0;

    memset(&iwr, 0, sizeof(iwr));
    os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
    iwr.u.essid.pointer = (caddr_t) buf;
    iwr.u.essid.length = len;

    if (ioctl(drv->ioctl_sock, SIOCGIWESSID, &iwr) < 0) {
    perror("ioctl[SIOCGIWESSID]");
    ret = -1;
    } else
    ret = iwr.u.essid.length;

    return ret;
}
static int
ar6003_set_iface_flags(void *priv, int dev_up)
{
#if 0
    struct ar6003_driver_data *drv = priv;
    struct ifreq ifr;

    wpa_printf(MSG_DEBUG, "%s: dev_up=%d", __func__, dev_up);

    if (drv->ioctl_sock < 0)
    return -1;

    memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->iface, IFNAMSIZ);

    if (ioctl(drv->ioctl_sock, SIOCGIFFLAGS, &ifr) != 0) {
    perror("ioctl[SIOCGIFFLAGS]");
    return -1;
    }

    if (dev_up)
    ifr.ifr_flags |= IFF_UP;
    else
    ifr.ifr_flags &= ~IFF_UP;

    if (ioctl(drv->ioctl_sock, SIOCSIFFLAGS, &ifr) != 0) {
    perror("ioctl[SIOCSIFFLAGS]");
    return -1;
    }

    if (dev_up) {
    memset(&ifr, 0, sizeof(ifr));
    os_strlcpy(ifr.ifr_name, drv->iface, IFNAMSIZ);
    ifr.ifr_mtu = HOSTAPD_MTU;
    if (ioctl(drv->ioctl_sock, SIOCSIFMTU, &ifr) != 0) {
        perror("ioctl[SIOCSIFMTU]");
        printf("Setting MTU failed - trying to survive with "
               "current value\n");
    }
    }
#endif
    return 0;
}

static int
ar6003_deinit_ap(void *priv)
{
    struct ar6003_driver_data *drv = priv;
    struct iwreq iwr;

    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);

    iwr.u.essid.flags = 0; /* ESSID off */

    if (ioctl(drv->ioctl_sock, SIOCSIWESSID, &iwr) < 0) {
        perror("ioctl[SIOCSIWESSID]");
        return -1;
    }
    return 0;
}

static int
ar6003_commit(void *priv)
{
    struct ar6003_driver_data *drv = priv;
    struct iwreq iwr;

    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);

    if (ioctl(drv->ioctl_sock, SIOCSIWCOMMIT, &iwr) < 0) {
    perror("ioctl[SIOCSIWCOMMIT]");
    return -1;
    }
    return ar6003_set_iface_flags(priv, 1);
}


static int
ar6003_set_wps_ie(void *priv, const u8 *iebuf, size_t iebuflen, u32 frametype)
{
    u8 buf[256];
    struct ieee80211req_getset_appiebuf * ie;

    ((int *)buf)[0] = AR6000_XIOCTL_WMI_SET_APPIE;
    ie = (struct ieee80211req_getset_appiebuf *) &buf[4];
    ie->app_frmtype = frametype;
    ie->app_buflen = iebuflen;
    if (iebuflen > 0)
    os_memcpy(&(ie->app_buf[0]), iebuf, iebuflen);
    
    return set80211priv(priv, AR6000_IOCTL_EXTENDED, buf,
        sizeof(struct ieee80211req_getset_appiebuf) + iebuflen);
}
#ifdef CONFIG_WPS
static int
ar6003_set_ap_wps_ie(void *priv, const struct wpabuf *beacon,
                  const struct wpabuf *proberesp)
{
    if (ar6003_set_wps_ie(priv, beacon ? wpabuf_head(beacon) : NULL,
                           beacon ? wpabuf_len(beacon) : 0,
                           IEEE80211_APPIE_FRAME_BEACON))
            return -1;
    return ar6003_set_wps_ie(priv,
                              proberesp ? wpabuf_head(proberesp) : NULL,
                              proberesp ? wpabuf_len(proberesp): 0,
                              IEEE80211_APPIE_FRAME_PROBE_RESP);
}
#else /* CONFIG_WPS */
#define madwifi_set_ap_wps_ie NULL
#endif /* CONFIG_WPS */


#ifdef CONFIG_WPS
#ifdef IEEE80211_IOCTL_FILTERFRAME
static void ar6003_raw_receive(void *ctx, const u8 *src_addr, const u8 *buf,
            size_t len)
{
    struct ar6003_driver_data *drv = ctx;
    const struct ieee80211_mgmt *mgmt;
    const u8 *end, *ie;
    u16 fc;
    size_t ie_len;

    /* Send Probe Request information to WPS processing */

    if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req))
    return;
    mgmt = (const struct ieee80211_mgmt *) buf;

    fc = le_to_host16(mgmt->frame_control);
    if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT ||
    WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_PROBE_REQ)
    return;

    end = buf + len;
    ie = mgmt->u.probe_req.variable;
    ie_len = len - (IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req));

    hostapd_wps_probe_req_rx(drv->ctx, mgmt->sa, ie, ie_len);
}
#endif /* IEEE80211_IOCTL_FILTERFRAME */
#endif /* CONFIG_WPS */

const struct wpa_driver_ops wpa_driver_ar6003_ops= {
    .name               = "ar6003",
    .desc               = "Linux wireless extension for AR6003",
    .get_bssid          = ar6003_driver_get_bssid,
    .get_ssid           = ar6003_driver_get_ssid,
    .set_key            = ar6003_driver_set_key,
    .set_countermeasures = ar6003_driver_set_countermeasures,
    .scan2              = ar6003_driver_scan,
    .get_scan_results2  = ar6003_driver_get_scan_results,
    .deauthenticate     = ar6003_driver_deauthenticate,
    .disassociate       = ar6003_driver_disassociate,
    .associate          = ar6003_driver_associate,
    .init               = ar6003_driver_init,
    .deinit             = ar6003_driver_deinit,
    .add_pmkid          = ar6003_driver_add_pmkid,
    .remove_pmkid       = ar6003_driver_remove_pmkid,
    .flush_pmkid        = ar6003_driver_flush_pmkid,
    .get_capa           = ar6003_driver_get_capa,
    .set_operstate      = ar6003_driver_set_operstate,
    .set_ieee8021x      = ar6003_set_ieee8021x,
    .set_privacy        = ar6003_set_privacy,
    .set_key            = ar6003_set_key,
    .flush              = ar6003_flush,
    .set_generic_elem   = ar6003_set_opt_ie,
    .sta_set_flags      = ar6003_sta_set_flags,
    .hapd_send_eapol    = ar6003_send_eapol,
    .sta_disassoc       = ar6003_sta_disassoc,
    .sta_deauth         = ar6003_sta_deauth,
    .set_freq           = ar6003_set_freq,
    .hapd_set_ssid      = ar6003_set_ssid,
    .hapd_get_ssid      = ar6003_get_ssid,
    .commit             = ar6003_commit,
    .deinit_ap          = ar6003_deinit_ap,
#ifdef CONFIG_WPS
    .set_ap_wps_ie      = ar6003_set_ap_wps_ie,
#endif
#ifdef CONFIG_P2P
    .p2p_find           = ar6003_driver_p2p_find,
    .p2p_stop_find      = ar6003_driver_p2p_stop_find,
    .p2p_listen         = ar6003_driver_p2p_listen,
    .p2p_connect        = ar6003_driver_p2p_connect,
    .wps_success_cb     = ar6003_driver_wps_success_cb,
    .p2p_group_formation_failed =
              ar6003_driver_p2p_group_formation_failed,
    .p2p_set_params     = ar6003_driver_p2p_set_params,
    .p2p_group_init     = ar6003_driver_p2p_group_init,
    .p2p_invite         = ar6003_driver_p2p_invite,
    .p2p_auth_go_neg    = ar6003_driver_p2p_auth_go_neg,
    .p2p_reject         = ar6003_driver_p2p_reject,
    .p2p_prov_disc_req  = ar6003_driver_p2p_prov_disc,
    .p2p_set_config     = ar6003_driver_p2p_set_config,
    .p2p_peer           = ar6003_driver_p2p_peer,
#endif
};
