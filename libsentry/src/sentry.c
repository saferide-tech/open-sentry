#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <pthread.h>
#include "internal_api.h"

sentry_callback        sentry_cb = NULL;
bool                   init = false;
