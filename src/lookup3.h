/**
 * \file lookup3.h 
 * \brief Hash functions
 *
 * Copyright (c) 2006, Arno Wagner 
 * Derived from lookup3.c by Bob Jenkins, May 2006, Public Domain.
 * 
 * Author: Arno Wagner (arno@wagner.name) 
 * 
 * Some changes and modifications:
 * -Bernhard Tellenbach (bernhard.tellenbach@airmail.ch)
 * 
 * 
 * Distributed under the Gnu Public License version 2 or the modified
 * BSD license (see file COPYING)
 *
 *
 */

uint32_t hashlittle(const void *key, size_t length, uint32_t initval);

void hashlittle2(const void *key, /* the key to hash */
size_t length, /* length of the key */
uint32_t *pc, /* IN: primary initval, OUT: primary hash */
uint32_t *pb); /* IN: secondary initval, OUT: secondary hash */

