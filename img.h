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
#ifndef __IMG_H__
#define __IMG_H__


void hkr_clear_img_cache(void);
void hkr_clear_cfg(void);
int hkr_img_cache_init(void);
char * hkr_get_img_path(void);
char * hkr_get_img(char * img);
char * hkr_get_base_cfg_path(void);
int hkr_img_extract(char * img);
int hkr_img_exists(char * img);

#endif
