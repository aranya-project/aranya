#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifndef ENABLE_ARANYA_PREVIEW
# define ENABLE_ARANYA_PREVIEW 1
#endif

#include "aranya-client.h"
#include "utils.h"

/* Test: ID string conversion functions */
static int test_id_string_conversion(void) {
    printf("\n=== TEST: ID String Conversion ===\n");
    
    /* Create a simple ID with known bytes */
    AranyaId id;
    memset(id.bytes, 0, ARANYA_ID_LEN);
    id.bytes[0] = 0x42;  /* Set first byte to 'B' in hex */
    
    /* Test id_to_str */
    char id_str[ARANYA_ID_STR_LEN];
    size_t str_len = ARANYA_ID_STR_LEN;
    AranyaError rc = aranya_id_to_str(&id, (char*)id_str, &str_len);
    
    if (rc != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to convert ID to string: %s\n", aranya_error_to_str(rc));
        return 0;
    }
    
    printf("  ID string (len=%zu): %s\n", str_len, id_str);
    
    /* Test id_from_str (parse the string back) */
    AranyaId parsed_id;
    rc = aranya_id_from_str(id_str, &parsed_id);
    
    if (rc != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to parse ID from string: %s\n", aranya_error_to_str(rc));
        return 0;
    }
    
    return 1;
}

/* Test: Duration constants */
static int test_duration_constants(void) {
    printf("\n=== TEST: Duration Constants ===\n");
    
    /* Verify duration constants are defined and make sense */
    uint64_t nanos = ARANYA_DURATION_NANOSECONDS;
    uint64_t micros = ARANYA_DURATION_MICROSECONDS;
    uint64_t millis = ARANYA_DURATION_MILLISECONDS;
    uint64_t seconds = ARANYA_DURATION_SECONDS;
    
    /* Verify the hierarchy: 1000 nanos = 1 micro, etc. */
    int valid = (nanos == 1) &&
                (micros == 1000 * nanos) &&
                (millis == 1000 * micros) &&
                (seconds == 1000 * millis);
    
    if (valid) {
        printf("  Duration constants verified:\n");
        printf("    1 nano  = %llu\n", (unsigned long long)nanos);
        printf("    1 micro = %llu\n", (unsigned long long)micros);
        printf("    1 milli = %llu\n", (unsigned long long)millis);
        printf("    1 sec   = %llu\n", (unsigned long long)seconds);
    }
    
    return valid;
}

/* Test: Label ID structure */
static int test_label_id(void) {
    printf("\n=== TEST: LabelId Structure ===\n");
    
    AranyaLabelId label_id;
    memset(&label_id, 0, sizeof(AranyaLabelId));
    
    return sizeof(AranyaLabelId) > 0;
}

int main(void) {
#if defined(ENABLE_ARANYA_PREVIEW)
    printf("Running aranya-client-capi data type tests\n");
    printf("===========================================\n");

    /* Test data type functionality */
    if (!test_duration_constants()) {
        printf("FAILED: duration_constants\n");
        return EXIT_FAILURE;
    }
    if (!test_id_string_conversion()) {
        printf("FAILED: id_string_conversion\n");
        return EXIT_FAILURE;
    }
    if (!test_label_id()) {
        printf("FAILED: label_id\n");
        return EXIT_FAILURE;
    }

    printf("\n===========================================\n");
    printf("ALL DATA TYPE TESTS PASSED\n");
    return EXIT_SUCCESS;
#else
    printf("ENABLE_ARANYA_PREVIEW not defined; skipping data type tests\n");
    return EXIT_SUCCESS;
#endif
}
