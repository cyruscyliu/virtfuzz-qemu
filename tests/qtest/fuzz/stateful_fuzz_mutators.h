/*
 * Stateful Virtual-Device Fuzzing Target Mutators
 *
 * Copyright Red Hat Inc., 2020
 *
 * Authors:
 *  Qiang Liu <qiangliu@zju.edu.cn>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef STATEFUL_FUZZ_MUTATORS_H
#define STATEFUL_FUZZ_MUTATORS_H

#include "stateful_fuzz.h"

extern size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size,
        size_t MaxSize);

// Discard fragment [e1, e2][e3, e4, e5] -> [e1, e2]
// Size--
static size_t Mutate_EraseFragment(Input *input, uint8_t *Data,
        size_t Size, size_t MaxSize) { // discard
    if (Size >= MaxSize) return 0;
    if (input->n_events == 1) return 0;
    size_t Idx = (rand() % input->n_events) / 2 + 1;
    size_t Offset = get_event_offset(input, Idx);
    // erase the back fragment
    return Offset;
}

static size_t insert_event(uint8_t *Data, size_t Size,
        size_t MaxSize, uint8_t type) {
    if (Size >= MaxSize) return MaxSize;
    uint8_t if_id = get_possible_interface(type);
    if (if_id == INTERFACE_CLOCK_STEP) {
        Data[Size] = if_id;
        return Size + 9;
    } else if (if_id == INTERFACE_SOCKET_WRITE){
        if (Size + 5 + 13 >= MaxSize)
            return 0;
        Data[Size] = if_id;
        uint32_t sw_size = 13;
        memcpy(Data + Size + 1, (uint8_t *)&sw_size, 4);
        return Size + 5 + 13;
    } else {
        switch (type) {
            case EVENT_TYPE_PIO_READ:
            case EVENT_TYPE_MMIO_READ:
                Data[Size] = if_id;
                return Size + 13;
            case EVENT_TYPE_PIO_WRITE:
            case EVENT_TYPE_MMIO_WRITE:
                Data[Size] = if_id;
                return Size + 21;
            default:
                fprintf(stderr, "Unsupport Event Type (insert_event)\n");
                return Size;
        }
    }
}

// Insert fragment [e1, e2] -> [e1, e2][e3, e4, e5].
// Before shuffle fragments.
// Size++
static size_t Mutate_InsertFragment(Input *input, uint8_t *Data,
        size_t Size, size_t MaxSize) { // insert
    if (Size >= MaxSize) return 0;
    if (input->n_events == 1) return 0;
    size_t N = (rand() % input->n_events) / 2 + 1;

    for (int i = 0; i < N; i ++) {
        Size = insert_event(Data, Size, MaxSize, rand() % N_VALID_TYPES);
        if (Size == 0 || Size >= MaxSize) return 0;
    }
    return Size;
}

// Shuffle fragments [e1, e2][e3, e4, e5] -> [e3, e4, e5][e1, e2].
// Size||
static size_t Mutate_ShuffleFragments(Input *input, uint8_t *Data,
        size_t Size, size_t MaxSize) { // swap
    if (Size >= MaxSize) return 0;
    if (input->n_events == 1) return 0;
    size_t Idx = (rand() % input->n_events) / 2 + 1;
    size_t Offset = get_event_offset(input, Idx);
    uint8_t *tmp = (uint8_t *)malloc(Offset);
    memcpy(tmp, Data, Offset);
    memmove(Data, Data + Offset, Size - Offset);
    memcpy(Data + Size - Offset, tmp, Offset);
    free(tmp);
    return Size;
}

// Size++||--
// Checked
static size_t CopyPartof(Input *input, uint8_t *Data, size_t Size, size_t MaxSize,
        size_t FromBeg, size_t ToBeg) {
    size_t FromBegOffset = get_event_offset(input, FromBeg);
    size_t ToBegOffset = get_event_offset(input, ToBeg);
    size_t CopyBytes = get_event_size(input, FromBeg);
    size_t RemainingLen;
    if (ToBeg + 1 == input->n_events) {
        RemainingLen = 0;
    } else {
        RemainingLen = Size - get_event_offset(input, ToBeg + 1);
    }
    Size = ToBegOffset + CopyBytes + RemainingLen;
    if (Size >= MaxSize) return 0;
    if (!RemainingLen) {
        // save back events
        uint8_t *saved = (uint8_t *)malloc(RemainingLen);
        memcpy(saved, Data + ToBegOffset + get_event_offset(input, ToBeg), RemainingLen);
        // copy
        memmove(Data + ToBegOffset, Data + FromBegOffset, CopyBytes);
        // restore events
        memcpy(Data + ToBegOffset + CopyBytes, saved, RemainingLen);
        // recal size
        free(saved);
    } else {
        memmove(Data + ToBegOffset, Data + FromBegOffset, CopyBytes);
    }
    return Size;
}

// Copy part of one fragment to another fragment.
// [e1, e2][e3, e4, e5] -> [e1, e2][e3, e1, e5]
// Before shuffle fragments.
// Size++||--
static size_t Mutate_CopyPartOfFragment(Input *input, uint8_t *Data,
        size_t Size, size_t MaxSize) { // override
    return 0;
    if (Size >= MaxSize) return 0;
    if (input->n_events == 1) return 0;
    size_t Idx = (rand() % input->n_events) / 2 + 1;
    size_t ToBeg = (rand() % (input->n_events - Idx)) + Idx;
    size_t FromBeg = (rand() % Idx);

    return CopyPartof(input, Data, Size, MaxSize, FromBeg, ToBeg);
}

// CrossOver fragments [e1, e2][e3, e4, e5] -> [e1, e3][e3, e2, e4].
// Size||
static size_t Mutate_CrossOverFragments(Input *input, uint8_t *Data,
        size_t Size, size_t MaxSize) { // crossover
    return 0;
    if (Size >= MaxSize) return 0;
    if (input->n_events <= 2) return 0;
    size_t Idx = (rand() % input->n_events) / 2 + 1;
    size_t IdxOffset = get_event_offset(input, Idx);
    size_t LeftEventIdx = (rand() % Idx);
    size_t RightEventIdx = (rand() % (input->n_events - Idx)) + Idx;

    size_t LeftEventBytes = get_event_size(input, LeftEventIdx);
    size_t RightEventBytes = get_event_size(input, RightEventIdx);
    size_t ContainerSize;
    if (RightEventBytes > LeftEventBytes)
        ContainerSize = Size + RightEventBytes - LeftEventBytes;
    else
        ContainerSize = Size + LeftEventBytes - RightEventBytes;

    uint8_t *Data1 = (uint8_t *)malloc(ContainerSize);
    uint8_t *Data2 = (uint8_t *)malloc(ContainerSize);
    memcpy(Data1, Data, Size);
    memcpy(Data2, Data, Size);

    size_t Size1 = CopyPartof(input, Data1, Size, MaxSize, LeftEventIdx, RightEventIdx);
    size_t Size2 = CopyPartof(input, Data2, Size, MaxSize, RightEventIdx, LeftEventIdx);
    if (Size1 == 0 || Size2 == 0) {
        free(Data1);
        free(Data2);
        return 0;
    }
    size_t FrontSize = Size2 - (Size - IdxOffset);
    memcpy(Data, Data2, FrontSize);
    size_t BackSize = Size1 - IdxOffset;
    memcpy(Data + FrontSize, Data1 + IdxOffset, BackSize);
    free(Data1);
    free(Data2);

    return Size;
}

static size_t Mutate_AddFragmentFromManualDictionary(Input *input, uint8_t *Data,
        size_t Size, size_t MaxSize) { // dictionary
    if (Size >= MaxSize) return 0;
    if (input->n_events == 1) return 0;
    return Size;
}

static size_t Mutate_AddFragmentFromPersistentAutoDictionary(Input *input, uint8_t *Data,
        size_t Size, size_t MaxSize) { // dictionary
    if (Size >= MaxSize) return 0;
    if (input->n_events == 1) return 0;
    return Size;
}

// Discard event [e1, e2, e3] -> [e1, e2].
// Size--
static size_t Mutate_EraseEvent(Input *input, uint8_t *Data,
        size_t Size, size_t MaxSize) { // discard
    if (Size >= MaxSize) return 0;
    size_t Idx = rand() % input->n_events;
    size_t IdxOffset = get_event_offset(input, Idx);
    size_t EraseBytes = get_event_size(input, Idx);
    memmove(Data + IdxOffset,
            Data + IdxOffset + EraseBytes,
            Size - IdxOffset - EraseBytes);
    return Size - EraseBytes;
}

// Insert event [e1, e2, e3] -> [e1, e2, e3, e4].
// Size++
static size_t Mutate_InsertEvent(Input *input, uint8_t *Data,
        size_t Size, size_t MaxSize) { // insert
    if (Size >= MaxSize) return 0;
    Size = insert_event(Data, Size, MaxSize, rand() % N_VALID_TYPES);
    if (Size >= MaxSize) return 0;
    return Size;
}

// Insert repeated event [e1, e2, e3] -> [e1, e2, e3, e4, e4, e4]
// Size++
// Checked
static size_t Mutate_InsertRepeatedEvent(Input *input, uint8_t *Data,
        size_t Size, size_t MaxSize) { // duplicate
    if (Size >= MaxSize) return 0;
    uint8_t type = rand() % N_VALID_TYPES;
    size_t kMinEventsToInsert = 3;
    size_t kMaxEventsToInsert = 8;
    size_t N = (rand() % (kMaxEventsToInsert - kMinEventsToInsert))
        + kMinEventsToInsert;
    for (int i = 0; i < N; i++) {
        Size = insert_event(Data, Size, MaxSize, type);
        if (Size >= MaxSize) return 0;
    }
    return Size;
}

// Shuffle events [e1, e2, e3] -> [e3, e1, e2]
// Size||
// Checked
static size_t Mutate_ShuffleEvents(Input *input, uint8_t *Data,
        size_t Size, size_t MaxSize) { //shuffle
    uint8_t *tmp = (uint8_t *)malloc(Size);
    memcpy(tmp, Data, Size);
    uint8_t *dirty = (uint8_t *)malloc(input->n_events);
    memset(dirty, 0, input->n_events);
    size_t event_size, Offset = 0;

    for (int i = 0, j = 0; i < input->n_events; i++) {
        j = rand() % input->n_events;
        if (dirty[j]) {
            // dirty
            i--;
        } else {
            dirty[j] = 1;
            event_size = get_event_size(input, j);
            memcpy(Data + Offset, tmp + get_event_offset(input, j), event_size);
            Offset += event_size;
        }
    }
    free(tmp);
    free(dirty);
    return Size;
}

static size_t Mutate_AddEventFromManualDictionary(Input *input,
        uint8_t *Data, size_t Size, size_t MaxSize) { // dictionary
    return Size;
}

static size_t Mutate_AddEventFromPersistentAutoDictionary(Input *input,
        uint8_t *Data, size_t Size, size_t MaxSize) { // dictionary
    return Size;
}

// Size||
// Choose the type with the same format to change.
static size_t Mutate_ChangeId(Input *input, uint8_t *Data,
        size_t Size, size_t MaxSize) { // random
    if (Size >= MaxSize) return 0;
    size_t Idx = (rand() % input->n_events);
    size_t IdxOffset = get_event_offset(input, Idx);
    uint8_t OldId = around_event_id(Data[IdxOffset]);
    if (OldId == INTERFACE_CLOCK_STEP ||
            OldId == INTERFACE_MEM_READ ||
            OldId == INTERFACE_MEM_WRITE ||
            OldId == INTERFACE_SOCKET_WRITE)
        return Size;

    InterfaceDescription ed = Id_Description[OldId];
    uint8_t *id_candidates = (uint8_t *)malloc(n_interfaces);
    uint8_t index = 0;
    for (int i = 0; i < n_interfaces; i++) {
         if (ed.type == Id_Description[i].type) {
             id_candidates[index] = i;
             index++;
         }
    }
    Data[IdxOffset] = id_candidates[rand() % index];
    free(id_candidates);
    return Size;
}

// Size||
static size_t Mutate_ChangeAddr(Input *input, uint8_t *Data,
        size_t Size, size_t MaxSize) { // random
    if (Size >= MaxSize) return 0;
    size_t Idx = (rand() % input->n_events);
    size_t IdxOffset = get_event_offset(input, Idx);
    uint8_t if_id = around_event_id(Data[IdxOffset]);
    uint8_t type = Id_Description[if_id].type;
    switch (type) {
        case EVENT_TYPE_PIO_READ:
        case EVENT_TYPE_MMIO_READ:
        case EVENT_TYPE_PIO_WRITE:
        case EVENT_TYPE_MMIO_WRITE:
            LLVMFuzzerMutate(Data + IdxOffset + 1, 8, 8);
            return Size;
        case EVENT_TYPE_CLOCK_STEP:
        case EVENT_TYPE_SOCKET_WRITE:
            return Size;
        default:
            fprintf(stderr, "Unsupport Event Type (Mutate_ChangeAddr)\n");
            return Size;
    }
}

// Size||++
static size_t Mutate_ChangeSize(Input *input, uint8_t *Data,
        size_t Size, size_t MaxSize) { // random
    if (Size >= MaxSize) return 0;
    size_t Idx = (rand() % input->n_events);
    size_t IdxOffset = get_event_offset(input, Idx);
    uint8_t if_id = around_event_id(Data[IdxOffset]);
    uint8_t type = Id_Description[if_id].type;
    size_t OldSize, NewSize, RemainingLen;
    switch (type) {
        case EVENT_TYPE_PIO_READ:
        case EVENT_TYPE_MMIO_READ:
        case EVENT_TYPE_PIO_WRITE:
        case EVENT_TYPE_MMIO_WRITE:
            LLVMFuzzerMutate(Data + IdxOffset + 9, 4, 4);
            return Size;
        case EVENT_TYPE_CLOCK_STEP:
            return Size;
        case EVENT_TYPE_SOCKET_WRITE:
            OldSize = get_event_size(input, Idx) - 5;
            NewSize = rand() % SOCKET_WRITE_MAX_SIZE;
            if (NewSize - OldSize + Size >= MaxSize)
                return 0;
            RemainingLen = Size - (IdxOffset + 1 + 4 + OldSize);
	        // printf("OldSize=%zu, NewSize=%zu, RemainingLen=%zu, Size=%zu, IdxOffset=%zu\n", OldSize, NewSize, RemainingLen, Size, IdxOffset);
            memcpy(Data + IdxOffset + 1, (uint8_t *)&NewSize, 4);
            memmove(Data + IdxOffset + 1 + 4 + NewSize, Data + IdxOffset + 1 + 4 + OldSize, RemainingLen);
            return Size + NewSize - OldSize;
        default:
            fprintf(stderr, "Unsupport Event Type (Mutate_ChangeSize)\n");
            return Size;
    }
}

// Size||
static size_t Mutate_ChangeValue(Input *input, uint8_t *Data,
        size_t Size, size_t MaxSize) { // random
    if (Size >= MaxSize) return 0;
    size_t Idx = (rand() % input->n_events);
    size_t IdxOffset = get_event_offset(input, Idx);
    uint8_t if_id = around_event_id(Data[IdxOffset]);
    uint8_t type = Id_Description[if_id].type;
    uint32_t sw_size;
    switch (type) {
        case EVENT_TYPE_PIO_READ:
        case EVENT_TYPE_MMIO_READ:
            return Size;
        case EVENT_TYPE_PIO_WRITE:
        case EVENT_TYPE_MMIO_WRITE:
            LLVMFuzzerMutate(Data + IdxOffset + 13, 4, 4);
            return Size;
        case EVENT_TYPE_CLOCK_STEP:
            LLVMFuzzerMutate(Data + IdxOffset + 1, 8, 8);
            return Size;
        case EVENT_TYPE_SOCKET_WRITE:
            memcpy((uint8_t *)&sw_size, Data + IdxOffset + 1, 4);
            if (sw_size)
                LLVMFuzzerMutate(Data + IdxOffset + 1 + 4, sw_size, sw_size);
            return Size;
        default:
            fprintf(stderr, "Unsupport Event Type (Mutate_ChangeValue)\n");
            return Size;
    }
}

static int select_mutators(int rand) {
    return rand % 11;
}

static int select_weighted_mutators(int rand) {
    int t = 6 * 1 + 7 * 4;
    rand = rand % t;

    if (rand < 6) {
        return rand;
    } else {
        return 6 + (rand - 6) / 4;
    }
}

#define N_MUTATORS 17
static size_t (* CustomMutators[])(Input *input, uint8_t *Data,
        size_t Size, size_t MaxSize) = {
    Mutate_EraseFragment, // * 0
    Mutate_InsertFragment, // * 1
    Mutate_ShuffleFragments, // * 2
    Mutate_ShuffleEvents, // * 3
    Mutate_EraseEvent, // 0
    Mutate_InsertEvent, // 1
    Mutate_InsertRepeatedEvent, // 2
    Mutate_ChangeId, // 3
    Mutate_ChangeAddr, // 4
    Mutate_ChangeSize, // 5
    Mutate_ChangeValue, // 6
    Mutate_CopyPartOfFragment, // * 4
    Mutate_CrossOverFragments, // * 5
    Mutate_AddFragmentFromManualDictionary, // * 0
    Mutate_AddFragmentFromPersistentAutoDictionary, // * 1
    Mutate_AddEventFromManualDictionary, // 2
    Mutate_AddEventFromPersistentAutoDictionary, // 3
};

const char *CustomMutatorNames[N_MUTATORS] = {
    "Mutate_EraseFragment",
    "Mutate_InsertFragment",
    "Mutate_ShuffleFragments",
    "Mutate_ShuffleEvents",
    "Mutate_EraseEvent",
    "Mutate_InsertEvent",
    "Mutate_InsertRepeatedEvent",
    "Mutate_ChangeId",
    "Mutate_ChangeAddr",
    "Mutate_ChangeSize",
    "Mutate_ChangeValue",
    "Mutate_CopyPartOfFragment",
    "Mutate_CrossOverFragments",
    "Mutate_AddFragmentFromManualDictionary",
    "Mutate_AddFragmentFromPersistentAutoDictionary",
    "Mutate_AddEventFromManualDictionary",
    "Mutate_AddEventFromPersistentAutoDictionary",
};
#endif /* STATEFUL_FUZZ_MUTATORS_H */
