/*
 * Type-Aware Virtual-Device Fuzzing
 *
 * Copyright Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "videzzo.h"

void *group_mutator_handler_test(
        Input *current_input, uint32_t current_event) {
    // basically, we have to duplicate the current event
    // in order to reissue it when GroupMutatorMiss returns
    Event *orig = get_event(current_input, current_event);
    Event *copy= (Event *)calloc(sizeof(Event), 1);
    event_ops[copy->type].deep_copy(orig, copy);
    insert_event(current_input, copy, current_event + 1);
}

FeedbackHandler group_mutator_handlers[0xff] = {
    [1] = group_mutator_handler_test,
};
