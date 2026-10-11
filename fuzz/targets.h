#include <stdint.h>
#include <stddef.h>
void core_canonical_run(const unsigned char* data, size_t data_len);
void core_state_machine_run(const unsigned char* data, size_t data_len);
void core_text_bounded_run(const unsigned char* data, size_t data_len);
void core_text_ident_run(const unsigned char* data, size_t data_len);
void core_text_json_run(const unsigned char* data, size_t data_len);
void proto_dto_run(const unsigned char* data, size_t data_len);
void proto_version_run(const unsigned char* data, size_t data_len);
void smoke_run(const unsigned char* data, size_t data_len);
void storage_identity_run(const unsigned char* data, size_t data_len);
void storage_policy_snapshot_run(const unsigned char* data, size_t data_len);
void storage_source_refs_run(const unsigned char* data, size_t data_len);
void tls_fingerprint_run(const unsigned char* data, size_t data_len);
void tls_pem_run(const unsigned char* data, size_t data_len);
