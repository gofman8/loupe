#include <stdint.h>
#include <stddef.h>
void core_canonical_run(const unsigned char* data, size_t data_len);
void core_text_bounded_run(const unsigned char* data, size_t data_len);
void core_text_ident_run(const unsigned char* data, size_t data_len);
void smoke_run(const unsigned char* data, size_t data_len);
