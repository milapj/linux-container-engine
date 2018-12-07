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
#ifndef __NET_H__
#define __NET_H__

int hkr_net_init(void);
int hkr_net_deinit(void);

int hkr_net_get_img(char * img);

#endif
