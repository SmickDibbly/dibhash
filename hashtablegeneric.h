#ifndef HASHTABLEGENERIC_H
#define HASHTABLEGENERIC_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/**
   A generic hash table with open-addressing and linear probing for collision
   resolution.

   The keys and (optional) values are not exposed to the table; instead,
   pointers to the keys and (optional) values are used in the form of GenericKey
   and GenericVal, respectively, both of which are typedefs of void *.

   In addition to keys and values, some callback functions must be provided:

   1) The hash function, which receives the table size and a GenericKey, and
   which must cast the GenericKey to the correct pointer type so that the actual
   key can be operated upon. The hash function must return a size_t value that
   is strictly less than the table size.

   2) A key comparison function, which receives two GenericKey values, casts
   them to the correct pointer type for data access, and then returns "true" if
   the keys are "equal" and returns "false" if the keys are "unequal". The hash
   table does not know or care about what "equal" or "unequal" actually mean.

   I assume this is cache-unfriendly, but I haven't tested it (TODO 2023-04-09).
*/

typedef struct HashTableGeneric HashTableGeneric;

typedef void *GenericKey;
typedef void *GenericVal;
typedef struct GenericKeyVal {
    GenericKey key;
    GenericVal val;
} GenericKeyVal;

typedef size_t (*fn_hash)(size_t mod, GenericKey key);
typedef bool (*fn_eqkey)(GenericKey key1, GenericKey key2);

typedef struct GenericReturnVal {
    int64_t index;
    GenericVal val;
} GenericReturnVal;

extern HashTableGeneric *create_HashTableGeneric
(size_t num_inputs, GenericKeyVal inputs[],
 fn_hash hash, fn_eqkey equals);

extern void destroy_HashTableGeneric(HashTableGeneric *table);

extern GenericReturnVal lookup_HashTableGeneric(HashTableGeneric *table, GenericKey key);

extern GenericReturnVal insert_HashTableGeneric(HashTableGeneric *table, GenericKey key, GenericVal val);

typedef void (*fn_printentry)(size_t index, GenericKey key, GenericVal val);
extern void print_HashTableGeneric(HashTableGeneric *table, fn_printentry cb_print);

#endif /* HASHTABLEGENERIC_H */
