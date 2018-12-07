/* 
 * This file is part of the Hawker container engine developed by
 * the HExSA Lab at Illinois Institute of Technology.
 *
 * Copyright (c) 2018, Kyle C. Hale <khale@cs.iit.edu>
 *
 * All rights reserved.
 *
 * Author: Kyle C. Hale <khale@cs.iit.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the 
 * file "LICENSE.txt".
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <curl/curl.h>
#include <sys/stat.h>

#include "hawker.h"
#include "img.h"


#define URL_BASE "http://cs.iit.edu/~khale/class/vm-class/f18/"

static size_t 
write_cb (void *ptr, size_t size, size_t nmemb, FILE * stream)
{
    size_t written = fwrite(ptr, size, nmemb, stream);
	return written;
}


int 
hkr_net_init (void)
{
    curl_global_init(CURL_GLOBAL_ALL);
    return 0;
}


void
hkr_net_deinit (void)
{
	curl_global_cleanup();
}


int
hkr_net_get_img (char * img)
{
    CURL * curl_handle;
    CURLcode res;
    char img_url[PATH_MAX];
	int prtall = 0;
    FILE * fp;
    char outfile[PATH_MAX];

    snprintf(outfile, PATH_MAX, "%s/%s.txz", hkr_get_img_path(), img);

    fp = fopen(outfile, "wb");
    if (!fp) {
        fprintf(stderr, "Couldn't open file (%s) for writing: %s\n", outfile, strerror(errno));
        return -1;
    }

    memset(img_url, 0, PATH_MAX);
    snprintf(img_url, PATH_MAX, "%s%s.txz", URL_BASE, img);

    curl_handle = curl_easy_init();

	curl_easy_setopt(curl_handle, CURLOPT_URL, img_url);
    curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, 1); // if we get not found, die
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, fp);

	// provide a useragent
	curl_easy_setopt(curl_handle, CURLOPT_USERAGENT,
			"libcurl-hawker-agent/" VERSION_STRING);

    printf("Downloading image %s\n", img);

    printf("pulling from %s\n", img_url);

	// get the image
	res = curl_easy_perform(curl_handle);

	if (res == CURLE_OK) {

		curl_off_t val;

		/* check for bytes downloaded */ 
		res = curl_easy_getinfo(curl_handle, CURLINFO_SIZE_DOWNLOAD_T, &val);
		if ((res == CURLE_OK) && (val > 0)) {
			printf("Data downloaded: %" CURL_FORMAT_CURL_OFF_T " bytes.\n", val);
		}

		/* check for total download time */ 
		res = curl_easy_getinfo(curl_handle, CURLINFO_TOTAL_TIME_T, &val);
		if ((res == CURLE_OK) && (val > 0)) {
			printf("Total download time: %" CURL_FORMAT_CURL_OFF_T ".%06ld sec.\n",
					(val / 1000000), (long)(val % 1000000));
		}

		/* check for average download speed */ 
		res = curl_easy_getinfo(curl_handle, CURLINFO_SPEED_DOWNLOAD_T, &val);
		if((CURLE_OK == res) && (val>0))
			printf("Average download speed: %" CURL_FORMAT_CURL_OFF_T
					" kbyte/sec.\n", val / 1024);

		if(prtall) {
			/* check for name resolution time */ 
			res = curl_easy_getinfo(curl_handle, CURLINFO_NAMELOOKUP_TIME_T, &val);
			if((CURLE_OK == res) && (val>0))
				printf("Name lookup time: %" CURL_FORMAT_CURL_OFF_T ".%06ld sec.\n",
						(val / 1000000), (long)(val % 1000000));

			/* check for connect time */ 
			res = curl_easy_getinfo(curl_handle, CURLINFO_CONNECT_TIME_T, &val);
			if ((res == CURLE_OK) && (val > 0))
				printf("Connect time: %" CURL_FORMAT_CURL_OFF_T ".%06ld sec.\n",
						(val / 1000000), (long)(val % 1000000));
		}
	} else {
		//fprintf(stderr, "Error while fetching '%s' : %s\n", img_url, curl_easy_strerror(res));
        goto out_err;
	}

    printf("Pull complete\n");

    printf("Downloaded image for '%s'\n", img);

	/* cleanup curl stuff */ 
	curl_easy_cleanup(curl_handle);

    fclose(fp);

	return 0;

out_err:
    fclose(fp);
    unlink(outfile);
    curl_easy_cleanup(curl_handle);
    return -1;
}
