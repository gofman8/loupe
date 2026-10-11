#include <stdint.h>
#include <stddef.h>
void cli_render_run(const unsigned char* data, size_t data_len);
void core_canonical_run(const unsigned char* data, size_t data_len);
void core_state_machine_run(const unsigned char* data, size_t data_len);
void core_text_bounded_run(const unsigned char* data, size_t data_len);
void core_text_ident_run(const unsigned char* data, size_t data_len);
void core_text_json_run(const unsigned char* data, size_t data_len);
void core_text_repo_path_run(const unsigned char* data, size_t data_len);
void proto_dto_run(const unsigned char* data, size_t data_len);
void proto_version_run(const unsigned char* data, size_t data_len);
void server_capability_header_run(const unsigned char* data, size_t data_len);
void server_config_run(const unsigned char* data, size_t data_len);
void smoke_run(const unsigned char* data, size_t data_len);
void storage_identity_run(const unsigned char* data, size_t data_len);
void storage_policy_snapshot_run(const unsigned char* data, size_t data_len);
void storage_source_refs_run(const unsigned char* data, size_t data_len);
void tls_fingerprint_run(const unsigned char* data, size_t data_len);
void tls_pem_run(const unsigned char* data, size_t data_len);
void web_api_run(const unsigned char* data, size_t data_len);
void worker_broker_policy_run(const unsigned char* data, size_t data_len);
void worker_broker_usage_run(const unsigned char* data, size_t data_len);
void worker_extract_json_run(const unsigned char* data, size_t data_len);
void worker_mcp_submission_run(const unsigned char* data, size_t data_len);
void worker_server_response_run(const unsigned char* data, size_t data_len);
