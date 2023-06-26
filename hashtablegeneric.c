#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

//#include "./dibhash.h"
#include "./hashtablegeneric.h"

// +------------------+
// | HashTableGeneric |
// +------------------+

#define MAX_LOAD_FACTOR (0.7)
#define MIN_LOAD_FACTOR (MAX_LOAD_FACTOR/4.0)
#define TEMP_EMPTY (-1)

typedef struct GenericEntry {
    bool empty;
    GenericKey key;
    GenericVal val;
} GenericEntry;

struct HashTableGeneric {
    fn_hash hash;
    fn_eqkey equals;
    float load_factor;
    size_t num_stored;
    size_t size;
    GenericEntry *entries;
};

static inline void clear_HashTableGeneric(size_t size, GenericEntry *entries) {
    for (size_t i_entry = 0; i_entry < size; i_entry++) {
        entries[i_entry].empty = true;
    }
}

HashTableGeneric *create_HashTableGeneric
(size_t num_inputs, GenericKeyVal inputs[],
 fn_hash hash, fn_eqkey equals) {
    float load_factor = 0;
    size_t num_stored = 0;
    
    size_t size = num_inputs;
    // round up size to next highest power of 2. There are branchless bithacky
    // ways to do this but who cares
    for (size_t i = 1; ; i *= 2) {
        if (size <= i && (float)num_inputs/(float)i < MAX_LOAD_FACTOR) {
            size = i;
            break;
        }
    }

    HashTableGeneric *table = malloc(sizeof(*table));
    if ( ! table) return NULL;
    table->entries = malloc(size*sizeof(*table->entries));
    if ( ! table->entries) {
        free(table);
        return NULL;
    }

    GenericEntry *entries = table->entries;

    table->hash = hash;
    table->equals = equals;
    
    // set all cells to empty
    clear_HashTableGeneric(size, entries);

    // load it up
    for (size_t i_in = 0; i_in < num_inputs; i_in++) {
        size_t i_entry = table->hash(size, inputs[i_in].key);
        while ( ! entries[i_entry].empty) {
            i_entry = (i_entry + 1) & (size - 1);
        }
        entries[i_entry].key = inputs[i_in].key;
        if (inputs[i_entry].val) entries[i_entry].val = inputs[i_in].val;
        else entries[i_entry].val = NULL;
        entries[i_entry].empty = false;
        num_stored++;
    }
    load_factor = (float)num_stored / (float)size;
    
    table->size = size;
    table->num_stored = num_stored;
    table->load_factor = load_factor;
    
    assert(load_factor <= MAX_LOAD_FACTOR);
    assert(MIN_LOAD_FACTOR <= load_factor);
    
    printf("Created a HashTableGeneric of size %zu, initially storing %zu entries for a load factor of %f.\n", table->size, table->num_stored, table->load_factor);
    
    return table;
}

static bool rehash_HashTableGeneric(HashTableGeneric *table) {
    size_t old_size = table->size;
    size_t new_size = 2 * old_size;

    size_t old_num_stored = table->num_stored;
    size_t new_num_stored = 0;

    float old_load_factor = table->load_factor;
    float new_load_factor = 0;
    
    GenericEntry *old_entries = table->entries;
    GenericEntry *new_entries = malloc(new_size*sizeof(*new_entries));
    if ( ! new_entries) return false;

    // clear new
    clear_HashTableGeneric(new_size, new_entries);

    // load it up
    for (size_t i_old = 0; i_old < old_size; i_old++) {
        if (old_entries[i_old].empty)
            continue;
        
        size_t i_new = table->hash(new_size, old_entries[i_old].key);

        while ( ! new_entries[i_new].empty) {
            i_new = (i_new + 1) & (new_size - 1);
        }
        new_entries[i_new] = old_entries[i_old];
        new_entries[i_new].empty = false;
        new_num_stored++;
    }
    new_load_factor = (float)new_num_stored / (float)new_size;

    free(table->entries);
    table->entries = new_entries;
    assert(old_num_stored == new_num_stored);
    table->size = new_size;
    table->load_factor = new_load_factor;

    assert(new_load_factor <= MAX_LOAD_FACTOR);
    assert(MIN_LOAD_FACTOR <= new_load_factor);

    printf("Rehashed HashTableGeneric\nSize: %zu -> %zu\nLoad factor: %f -> %f\n\n",
           old_size, new_size, old_load_factor, new_load_factor);
    
    return true;
}

void destroy_HashTableGeneric(HashTableGeneric *table) {
    if ( ! table)
        return;
    
    free(table->entries);
    free(table);
}


GenericReturnVal lookup_HashTableGeneric(HashTableGeneric *table, GenericKey key) {
    GenericReturnVal ret;
    
    size_t size = table->size;
    GenericEntry *entries = table->entries;
    size_t i_entry = table->hash(size, key);
    
    while ( ! entries[i_entry].empty) {
        if (table->equals(entries[i_entry].key, key)) {
            ret.index = i_entry;
            ret.val = entries[i_entry].val;
            return ret;
        } 
        i_entry = (i_entry + 1) & (size - 1);
    }

    ret.index = -1;
    ret.val = NULL;
    return ret;
}

GenericReturnVal insert_HashTableGeneric(HashTableGeneric *table, GenericKey key, GenericVal val) {
    /* If key already present, replace its value and return the old value. If
       key is not already present, insert it and return -1. */

    GenericReturnVal ret;
    
    size_t size = table->size;
    GenericEntry *entries = table->entries;
    size_t i_entry = table->hash(size, key);

    while ( ! entries[i_entry].empty) {
        if (table->equals(entries[i_entry].key, key)) {
            ret.index = i_entry;
            ret.val = entries[i_entry].val;
            entries[i_entry].key = key;
            if (val) entries[i_entry].val = val;
            else entries[i_entry].val = NULL;
            return ret;
        }
        i_entry = (i_entry + 1) & (size - 1);
    }

    entries[i_entry].key = key;
    entries[i_entry].val = val;
    entries[i_entry].empty = false;
    
    table->num_stored++;
    table->load_factor = (float)table->num_stored / (float)table->size;
    
    //printf("Insertion: [\"%s\" : \"%s\"]; load = %f\n", kvp.key, kvp.val, dict->load_factor);

    if (table->load_factor > MAX_LOAD_FACTOR) {
        rehash_HashTableGeneric(table);
    }

    ret.index = -1;
    ret.val = NULL;
    return ret;
}

void print_HashTableGeneric(HashTableGeneric *table, fn_printentry cb_print) {
    for (size_t i_entry = 0; i_entry < table->size; i_entry++) {
        if (table->entries[i_entry].empty)
            continue;
        
        cb_print(i_entry, table->entries[i_entry].key, table->entries[i_entry].val);
    }
}



/* -------------------------------------------------------------------------- */

// +-----------------------------+
// | IDList via HashTableGeneric |
// +-----------------------------+

typedef uint64_t IDListGenKey;
typedef struct IDListGen IDListGen; // implemented using HashTableGeneric

static size_t hash_IDListGen(size_t mod, GenericKey key) {
    return *(IDListGenKey *)key & (mod - 1);    
}

static bool equals_IDList2KeyGen(GenericKey key1, GenericKey key2) {
    return *(IDListGenKey *)key1 == *(IDListGenKey *)key2;
}

struct IDListGen {
    HashTableGeneric *table;
    GenericKey *keys;
};

IDListGen *create_IDListGen(size_t num_inputs, IDListGenKey in_keys[]) {
    IDListGen *list = malloc(sizeof(*list));
    if ( ! list) return NULL;

    list->keys = malloc(num_inputs*sizeof(*list->keys));
    for (size_t i_in = 0; i_in < num_inputs; i_in++) {
        list->keys[i_in] = (GenericKey)&in_keys[i_in];
    }

    list->table = create_HashTableGeneric(num_inputs, list->keys, NULL, hash_IDListGen, equals_IDList2KeyGen);
    
    return list;
}

void destroy_IDList2(IDListGen *list) {
    if (! list) return;
    
    destroy_HashTableGeneric(list->table);

    free(list->keys);
    free(list);
}

int64_t lookup_IDList2(IDListGen *list, IDListGenKey key) {
    GenericReturnVal ret = lookup_HashTableGeneric(list->table, &key);
    return ret.index;
}

int64_t insert_IDList2(IDListGen *list, IDListGenKey key) {
    GenericReturnVal ret = insert_HashTableGeneric(list->table, &key, NULL);
    return ret.index;
}

/* -------------------------------------------------------------------------- */

// +--------------------------------+
// | StrIDList via HashTableGeneric |
// +--------------------------------+

#define SEED 459
#define LSHIFT 5
#define RSHIFT 2

typedef char const *StrIDList2Key;
typedef struct StrIDList2 *StrIDList2;

static inline uint64_t str_hash_init(int seed) {
    return seed;
}

static inline uint64_t str_hash_final(size_t mod, uint64_t hash, int seed) {
    (void)seed;
    return hash & (mod - 1);
}

static inline uint64_t str_hash_step(size_t i, uint64_t hash, char ch) {
    (void)i;
    return hash ^ ((hash<<LSHIFT) + (hash>>RSHIFT) + ch);
}

static size_t str_hash_generickey(size_t mod, GenericKey key) {
    char const *str = *(StrIDList2Key *)key;
    uint64_t hash = str_hash_init(SEED);
    size_t len = strlen(str);
    
    for (size_t i_ch = 0; i_ch < len; i_ch++) {
        hash = str_hash_step(i_ch, hash, str[i_ch]);
    }

    return str_hash_final(mod, hash, SEED);
}

static bool str_equals_generickey(GenericKey key1, GenericKey key2) {
    return strcmp(*(StrIDList2Key *)key1, *(StrIDList2Key *)key2) == 0;
}

struct StrIDList2 {
    HashTableGeneric table;
    GenericKey *keys;
};

StrIDList2 create_StrIDList2(size_t num_inputs, StrIDList2Key in_keys[]) {
    StrIDList2 list = malloc(sizeof(*list));
    if ( ! list) return NULL;

    list->keys = malloc(num_inputs*sizeof(*list->keys));
    for (size_t i_in = 0; i_in < num_inputs; i_in++) {
        list->keys[i_in] = (GenericKey)&in_keys[i_in];
    }
    
    list->table = create_HashTableGeneric(num_inputs, list->keys, NULL, str_hash_generickey, str_equals_generickey);
    
    return list;
}

void destroy_StrIDList2(StrIDList2 list) {
    if (! list) return;
    
    destroy_HashTableGeneric(list->table);

    free(list->keys);
    free(list);
}

int64_t lookup_StrIDList2(StrIDList2 list, StrIDList2Key key) {
    GenericReturnVal ret = lookup_HashTableGeneric(list->table, &key);
    return ret.index;
}

int64_t insert_StrIDList2(StrIDList2 list, StrIDList2Key key) {
    GenericReturnVal ret = insert_HashTableGeneric(list->table, &key, NULL);
    return ret.index;
}

/* -------------------------------------------------------------------------- */

// +---------------------------------+
// | Dictionary via HashTableGeneric |
// +---------------------------------+

typedef struct DictGen *DictGen;

struct DictGen {
    HashTableGeneric table;
    GenericKeyVal *keyvals;
};

DictGen create_Dict2(size_t num_inputs, GenericKeyVal in_entries[]) {
    DictGen dict = malloc(sizeof(*dict));
    if ( ! dict) return NULL;

    dict->keyvals = malloc(num_inputs*sizeof(*dict->keyvals));
    for (size_t i_in = 0; i_in < num_inputs; i_in++) {
        dict->keyvals[i_in].key = (GenericKey)&in_entries[i_in].key;
        dict->keyvals[i_in].val = (GenericKey)&in_entries[i_in].val;
    }
    
    dict->table = create_HashTableGeneric(num_inputs, dict->keys, dict->vals, str_hash_generickey, str_equals_generickey);
    
    return dict;
}

void destroy_Dict2(Dict2 dict) {
    if (! dict) return;
    
    destroy_HashTableGeneric(dict->table);

    free(dict->keys);
    free(dict->vals);
    free(dict);
}

DictVal lookup_Dict2(Dict2 dict, DictKey *key) {
    GenericReturnVal ret = lookup_HashTableGeneric(dict->table, key);
    if (ret.index == -1) {
        return NULL;
    }
    else {
        assert(ret.val != NULL);
        return *(DictVal *)ret.val;
    }
}

DictVal insert_Dict2(Dict2 dict, DictKey *key, DictVal *val) {
    GenericReturnVal ret = insert_HashTableGeneric(dict->table, key, val);
    if (ret.index == -1) {
        return NULL;
    }
    else {
        assert(ret.val != NULL);
        return *(DictVal *)ret.val;
    }
}

static void cb_printKVP(size_t index, GenericKey key, GenericVal val) {
    printf("[%zu] : { \"%s\" : \"%s\" }\n", index, *(DictKey *)key, *(DictVal *)val);
}

void print_Dict2(Dict2 dict) {
    print_HashTableGeneric(dict->table, cb_printKVP);
}
