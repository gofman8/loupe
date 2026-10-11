# TLS regression fixtures

`invalid-subject-oid.pem` is the public certificate from continuous fuzzing
crash `dad5baa627946cef8466b57a9de75ef4066f7157`, with its one-byte field
selector removed. The exact 604-byte input is also retained under
`fuzz/test_cases/tls_pem/invalid-subject-oid`.

The certificate reaches rcgen's import path but produces unsupported OID
arcs in its subject name. Rebinding it previously panicked in yasna's OID
writer. The fixture contains no private key; the unit test generates one.
