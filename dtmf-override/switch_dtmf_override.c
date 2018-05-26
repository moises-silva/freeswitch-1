#define _GNU_SOURCE
 
#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>
 
typedef enum {
    SWITCH_STATUS_SUCCESS,
    SWITCH_STATUS_WINBREAK = 730035
} switch_status_t;

typedef enum {
    SWITCH_DTMF_UNKNOWN,
    SWITCH_DTMF_INBAND_AUDIO,
    SWITCH_DTMF_RTP,
    SWITCH_DTMF_ENDPOINT,
    SWITCH_DTMF_APP
} switch_dtmf_source_t;

typedef struct {
    char digit;
    uint32_t duration;
    int32_t flags;
    switch_dtmf_source_t source;
} switch_dtmf_t;

typedef switch_status_t (*orig_dtmf_enqueue_t)(void *channel, const switch_dtmf_t *dtmf);

switch_status_t switch_channel_queue_dtmf(void *channel, const switch_dtmf_t *dtmf)
{
	orig_dtmf_enqueue_t orig;
	fprintf(stderr, "dtmf override for dtmf %c of duration %ums\n", dtmf->digit, dtmf->duration);
	if (!dtmf->duration) {
		fprintf(stderr, "dropping dtmf %c of duration %ums\n", dtmf->digit, dtmf->duration);
		return SWITCH_STATUS_SUCCESS;
	}
	orig = (orig_dtmf_enqueue_t)dlsym(RTLD_NEXT, "switch_channel_queue_dtmf");
	return orig(channel, dtmf);
}
